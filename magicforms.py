__doc__ = """

    ===============
     magicforms.py
    ===============

    To use the magic forms, a secret key must be set in Django settings. It's
    used as a salt when calculating the magic token for the form.

    >>> from django.conf import settings
    >>> settings.configure(SECRET_KEY='secret')

    We'll use some tricks to fake the clock to an arbitrary time for testing
    purposes.

    >>> class FakeDateTime(datetime.datetime):
    ...     now = staticmethod(lambda: datetime._fake_now)
    >>> datetime.datetime = FakeDateTime

    The magic token on the form is constructed by concatenating the current
    time with a salted hash of the current time, remote IP address and unique
    ID (UID) of the request.  The unique ID might be e.g. the primary key of
    the blog post which is being commented on.

    >>> correct_magic = sign('1991-10-05 18:53:00', '1.2.3.4', 16)
    >>> correct_magic
    'MTk5MS0xMC0wNSAxODo1MzowMOkIsSohfdvUDd3b0orRUO-2KN3s'

    Let's use 1991-10-05 at 18:53:00 as the time the user loaded the form.

    >>> when_loaded = datetime.datetime(1991, 10, 5, 18, 53, 0)
    >>> datetime._fake_now = when_loaded

    We'll use a mock class to act as a form object:

    >>> class f:
    ...     remote_ip = '1.2.3.4'
    ...     unique_id = 16
    ...     data = {}
    ...     initial = {}

    The ``set_initial_magic`` function sets the initial value of the form's
    magic field according to current time, IP and UID.

    >>> set_initial_magic(f)
    >>> f.initial['magic'] == correct_magic
    True

    It won't set the initial value if it's already present in the form's data:

    >>> f.data = {'magic': 'something'} ; f.initial = {}
    >>> set_initial_magic(f)
    >>> f.initial
    {}

    The following function tests the ``clean_magic()`` function with different
    form data.  The default keyword argument values represent a correct
    submission 60 seconds after loading the form.

    >>> def test_clean(ip='1.2.3.4', uid=16, elapsed_secs=60, magic=correct_magic):
    ...     class f:
    ...         remote_ip = ip
    ...         unique_id = uid
    ...         cleaned_data = {'magic': magic}
    ...     datetime._fake_now = when_loaded + datetime.timedelta(seconds=elapsed_secs)
    ...     clean_magic(f)

    A correct submission throws no exceptions.

    >>> test_clean()

    If the IP address or unique ID don't match, the user is notified about a
    security violation.  This happens also if the security token has been
    tampered with.

    >>> test_clean(ip='1.2.3.5')
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']

    >>> test_clean(uid=17)
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']

    >>> test_clean(magic='wrong magic')
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']

    >>> test_clean(magic=b64encode('wrong magic'))
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']

    If the form is submitted less than five seconds after loading it, we have
    reason to believe the submitter was a bot.  A submission after over one
    hour is probably a result of a bot submitting the form it has saved
    earlier.

    >>> test_clean(elapsed_secs=2)
    Traceback (most recent call last):
    ValidationError: [u'Wait for another 3.00 seconds before submitting this form']

    >>> test_clean(elapsed_secs=3660)
    Traceback (most recent call last):
    ValidationError: [u'This form has expired. Reload the page to get a new one']

    To test the form class we'll reset the current time back to our chosen form
    load timestamp.

    >>> datetime._fake_now = when_loaded

    The magic form includes hidden ``author_bogus_name`` and ``magic`` fields.

    >>> f = MagicForm('1.2.3.4', 16)
    >>> print f
    <tr><th></th><td><input id="id_author_bogus_name" style="display:none" type="text" name="author_bogus_name" maxlength="0" /><input type="hidden" name="magic" value="MTk5MS0xMC0wNSAxODo1MzowMOkIsSohfdvUDd3b0orRUO-2KN3s" id="id_magic" /></td></tr>

    The following function tests the form validation with different form data.
    The default keyword argument values represent a correct submission 60
    seconds after loading the form.

    >>> def test_form(ip='1.2.3.4', uid=16, elapsed_secs=60, magic=correct_magic):
    ...     datetime._fake_now = when_loaded + datetime.timedelta(seconds=elapsed_secs)
    ...     f = MagicForm(ip, uid, data={'magic': magic})
    ...     return f.is_valid(), f.errors

    A correct submission validates correctly.

    >>> test_form()
    (True, {})

    If the IP address or unique ID don't match, the user is notified about a
    security violation.  This happens also if the security token has been
    tampered with.

    >>> test_form(ip='1.2.3.5')
    (False, {'magic': [u'Invalid security token']})

    >>> test_form(uid=17)
    (False, {'magic': [u'Invalid security token']})

    >>> test_form(magic='wrong magic')
    (False, {'magic': [u'Invalid security token']})

    >>> test_form(magic=b64encode('wrong magic'))
    (False, {'magic': [u'Invalid security token']})

    If the form is submitted less than five seconds after loading it, the form
    is invalid and the user is notified.

    >>> test_form(elapsed_secs=2)
    (False, {'magic': [u'Wait for another 3.00 seconds before submitting this form']})

    >>> test_form(elapsed_secs=3660)
    (False, {'magic': [u'This form has expired. Reload the page to get a new one']})

"""

from hashlib import sha1
import cPickle as pickle
import datetime
from base64 import urlsafe_b64encode as b64encode
from base64 import urlsafe_b64decode as b64decode

try:
    from django import newforms as forms
except ImportError:
    from django import forms

from django.conf import settings
from django.utils.translation import ugettext as _

MIN_WAIT_SECONDS = 5
MAX_WAIT_SECONDS = 3600

def sign(timestamp, ip, uid):
    data = pickle.dumps({'remote_ip': ip, 'unique_id': uid})
    signature = sha1(timestamp + data + settings.SECRET_KEY).digest()
    return b64encode(timestamp + signature)

def clean_magic(self):
    m = self.cleaned_data['magic']
    try:
        plain = b64decode(str(m))
        when_loaded_str = plain[:19]
        when_loaded = datetime.datetime.strptime(when_loaded_str, '%Y-%m-%d %H:%M:%S')
        assert m == sign(when_loaded_str, self.remote_ip, self.unique_id)
    except (TypeError, ValueError, AssertionError):
        raise forms.ValidationError(_('Invalid security token'))

    curdelta = datetime.datetime.now() - when_loaded

    mindelta = datetime.timedelta(seconds=MIN_WAIT_SECONDS)
    if curdelta < mindelta:
        d = mindelta - curdelta
        raise forms.ValidationError(_('Wait for another %.2f seconds before submitting this form') % (d.seconds + float(d.microseconds)/1000000))

    if curdelta > datetime.timedelta(seconds=MAX_WAIT_SECONDS):
        raise forms.ValidationError(_('This form has expired. Reload the page to get a new one'))

    return m

def set_initial_magic(self):
    if not self.data.get('magic'):
        curtime = str(datetime.datetime.now())
        self.initial['magic'] = sign(curtime, self.remote_ip, self.unique_id)


class MagicForm(forms.Form):
    magic = forms.CharField(max_length=1024, widget=forms.HiddenInput())
    author_bogus_name = forms.CharField(required=False, max_length=0, label='', widget=forms.TextInput(attrs={ 'style': 'display:none'}))

    def __init__(self, remote_ip, unique_id, *args, **kwargs):
        super(MagicForm, self).__init__(*args, **kwargs)
        self.remote_ip = remote_ip
        self.unique_id = unique_id
        set_initial_magic(self)

    def clean_magic(self):
        return clean_magic(self)

class MagicModelForm(forms.ModelForm):
    magic = forms.CharField(max_length=1024, widget=forms.HiddenInput())
    author_bogus_name = forms.CharField(required=False, max_length=0, label='', widget=forms.TextInput(attrs={ 'style': 'display:none'}))

    def __init__(self, remote_ip, unique_id, *args, **kwargs):
        super(MagicModelForm, self).__init__(*args, **kwargs)
        self.remote_ip = remote_ip
        self.unique_id = unique_id
        set_initial_magic(self)

    def clean_magic(self):
        return clean_magic(self)

if __name__ == '__main__':
    from doctest import testmod
    testmod()
