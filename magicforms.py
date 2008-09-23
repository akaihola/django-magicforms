from Crypto.Cipher import ARC4
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

def clean_magic(self):
    """
    >>> correct_magic = 'xVKiLYj38dNcosqplrmcU4o9AtCJuvVqeg8nwLkfJ2vWlHqkzDMd0SmOkLWky0Pn_B_58OTAOp0xq5VJdYkqfO9-umnQd3KgO7iPWl6psSVxK0PGfCEbQKsgq22Zd55jKFt99ItWj592F_Ba1hHaIyRgMJDNi292KwxcSA8qAwNWjqFuPlCLx1STft6BWciS'
    >>> when_loaded = datetime.datetime(1991, 10, 5, 18, 53, 0)

    >>> def test_clean(ip, uid, elapsed_secs, magic):
    ...     class f:
    ...         remote_ip = ip
    ...         unique_id = uid
    ...         cleaned_data = {'magic': magic}
    ...     datetime._fake_now = when_loaded + datetime.timedelta(seconds=elapsed_secs)
    ...     clean_magic(f)

    >>> test_clean('1.2.3.4', 16, 60, correct_magic)

    >>> test_clean('1.2.3.4', 16, 2, correct_magic)
    Traceback (most recent call last):
    ValidationError: [u'Wait for another 3.00 seconds before submitting this form']

    >>> test_clean('1.2.3.4', 16, 3660, correct_magic)
    Traceback (most recent call last):
    ValidationError: [u'This form has expired. Reload the page to get a new one']

    >>> test_clean('1.2.3.5', 16, 60, correct_magic)
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']

    >>> test_clean('1.2.3.4', 17, 60, correct_magic)
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']

    >>> test_clean('1.2.3.4', 16, 60, 'wrong magic')
    Traceback (most recent call last):
    ValidationError: [u'Invalid security token']
    """
    m = self.cleaned_data['magic']
    arc4 = ARC4.new(settings.SECRET_KEY)
    try:
        plain = arc4.decrypt(b64decode(str(m)))
        data = pickle.loads(plain)
        before = data['curtime']
        remote_ip = data['remote_ip']
        unique_id = data['unique_id']
    except (TypeError, pickle.UnpicklingError, KeyError):
        raise forms.ValidationError(_('Invalid security token'))

    if remote_ip != self.remote_ip or unique_id != self.unique_id:
        raise forms.ValidationError(_('Invalid security token'))

    try:
        curdelta = datetime.datetime.now() - before
    except TypeError:
        raise forms.ValidationError(_('Invalid security token'))

    mindelta = datetime.timedelta(seconds=MIN_WAIT_SECONDS)
    if curdelta < mindelta:
        d = mindelta - curdelta
        raise forms.ValidationError(_('Wait for another %.2f seconds before submitting this form') % (d.seconds + float(d.microseconds)/1000000))

    if curdelta > datetime.timedelta(seconds=MAX_WAIT_SECONDS):
        raise forms.ValidationError(_('This form has expired. Reload the page to get a new one'))

    return m

def set_initial_magic(self):
    """
    >>> class f:
    ...     remote_ip = '1.2.3.4'
    ...     unique_id = 16
    ...     data = {}
    ...     initial = {}
    >>> datetime._fake_now = datetime.datetime(1991, 10, 5, 18, 53, 0)
    >>> set_initial_magic(f)
    >>> f.initial['magic']
    'xVKiLYj38dNcosqplrmcU4o9AtCJuvVqeg8nwLkfJ2vWlHqkzDMd0SmOkLWky0Pn_B_58OTAOp0xq5VJdYkqfO9-umnQd3KgO7iPWl6psSVxK0PGfCEbQKsgq22Zd55jKFt99ItWj592F_Ba1hHaIyRgMJDNi292KwxcSA8qAwNWjqFuPlCLx1STft6BWciS'
    """
    if not self.data.get('magic'):
        arc4 = ARC4.new(settings.SECRET_KEY)
        data = {
            'curtime': datetime.datetime.now(),
            'remote_ip': self.remote_ip,
            'unique_id': self.unique_id,
        }
        plain = pickle.dumps(data)
        self.initial['magic'] = b64encode(arc4.encrypt(plain))

class MagicForm(forms.Form):
    """
    >>> datetime._fake_now = when_loaded = datetime.datetime(1991, 10, 5, 18, 53, 0)
    >>> correct_magic = 'xVKiLYj38dNcosqplrmcU4o9AtCJuvVqeg8nwLkfJ2vWlHqkzDMd0SmOkLWky0Pn_B_58OTAOp0xq5VJdYkqfO9-umnQd3KgO7iPWl6psSVxK0PGfCEbQKsgq22Zd55jKFt99ItWj592F_Ba1hHaIyRgMJDNi292KwxcSA8qAwNWjqFuPlCLx1STft6BWciS'

    >>> f = MagicForm('1.2.3.4', 16)
    >>> print f
    <tr><th></th><td><input id="id_author_bogus_name" style="display:none" type="text" name="author_bogus_name" maxlength="0" /><input type="hidden" name="magic" value="xVKiLYj38dNcosqplrmcU4o9AtCJuvVqeg8nwLkfJ2vWlHqkzDMd0SmOkLWky0Pn_B_58OTAOp0xq5VJdYkqfO9-umnQd3KgO7iPWl6psSVxK0PGfCEbQKsgq22Zd55jKFt99ItWj592F_Ba1hHaIyRgMJDNi292KwxcSA8qAwNWjqFuPlCLx1STft6BWciS" id="id_magic" /></td></tr>

    >>> def test_form(remote_id, unique_id, elapsed_secs, magic):
    ...     datetime._fake_now = when_loaded + datetime.timedelta(seconds=elapsed_secs)
    ...     f = MagicForm(remote_id, unique_id, data={'magic': magic})
    ...     return f.is_valid(), f.errors

    >>> test_form('1.2.3.4', 16, 60, correct_magic)
    (True, {})

    >>> test_form('1.2.3.4', 16, 2, correct_magic)
    (False, {'magic': [u'Wait for another 3.00 seconds before submitting this form']})

    >>> test_form('1.2.3.4', 16, 3660, correct_magic)
    (False, {'magic': [u'This form has expired. Reload the page to get a new one']})

    >>> test_form('1.2.3.5', 16, 60, correct_magic)
    (False, {'magic': [u'Invalid security token']})

    >>> test_form('1.2.3.5', 17, 60, correct_magic)
    (False, {'magic': [u'Invalid security token']})

    >>> test_form('1.2.3.5', 16, 60, 'wrong magic')
    (False, {'magic': [u'Invalid security token']})
    """
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
    from django.conf import settings
    settings.configure(SECRET_KEY='secret')

    global _fake_now
    class FakeDateTime(datetime.datetime):
        now = staticmethod(lambda: datetime._fake_now)
    datetime.datetime = FakeDateTime

    from doctest import testmod
    testmod()
