from scramp import ScramClient, ScramServer, ScramException
from scramp import core
import hashlib
import pytest

USERNAME = 'user'
PASSWORD = 'pencil'


SCRAM_SHA_1_EXCHANGE = {
    'cfirst': 'n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL',
    'sfirst': 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,'
    's=QSXCR+Q6sek8bf92,i=4096',
    'cfinal': 'c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,'
    'p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=',
    'sfinal': 'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=',
    'cfirst_bare': 'n=user,r=fyko+d2lbbFgONRv9qkxdawL',
    'c_nonce': 'fyko+d2lbbFgONRv9qkxdawL',
    's_nonce': '3rfcNHYJY1ZVvWVs7j',
    'nonce': 'fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j',
    'auth_message': 'n=user,r=fyko+d2lbbFgONRv9qkxdawL,'
    'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,'
    's=QSXCR+Q6sek8bf92,i=4096,c=biws,'
    'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j',
    'salt': 'QSXCR+Q6sek8bf92',
    'iterations': 4096,
    'server_signature': 'rmF9pqV8S7suAoZWja4dJRkFsKQ=',
    'hf': hashlib.sha1
}


SCRAM_SHA_256_EXCHANGE = {
    'cfirst': 'n,,n=user,r=rOprNGfwEbeRWgbNEkqO',
    'sfirst': 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
    's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096',
    'cfinal': 'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
    'p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=',
    'sfinal': 'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=',
    'cfirst_bare': 'n=user,r=rOprNGfwEbeRWgbNEkqO',
    'c_nonce': 'rOprNGfwEbeRWgbNEkqO',
    's_nonce': '%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
    'nonce': 'rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
    'auth_message': 'n=user,r=rOprNGfwEbeRWgbNEkqO,'
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
    's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,'
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
    'salt': 'W22ZaJ0SNY7soEsUEjb6gQ==',
    'iterations': 4096,
    'server_signature': '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=',
    'hf': hashlib.sha256
}


params = [
    ('SCRAM-SHA-1', SCRAM_SHA_1_EXCHANGE),
    ('SCRAM-SHA-256', SCRAM_SHA_256_EXCHANGE)
]


@pytest.mark.parametrize("mech,x", params)
def test_get_client_first(mech, x):
    cfirst_bare, cfirst = core._get_client_first(USERNAME, x['c_nonce'])

    assert cfirst_bare == x['cfirst_bare']
    assert cfirst == x['cfirst']


@pytest.mark.parametrize("mech,x", params)
def test_make_auth_message(mech, x):
    auth_msg = core._make_auth_message(
        x['nonce'], x['cfirst_bare'], x['sfirst'])
    assert auth_msg == x['auth_message']


@pytest.mark.parametrize("mech,x", params)
def test_get_client_final(mech, x):
    server_signature, cfinal = core._get_client_final(
        x['hf'], PASSWORD, x['salt'], x['iterations'], x['nonce'],
        x['auth_message'])

    assert server_signature == x['server_signature']
    assert cfinal == x['cfinal']


@pytest.mark.parametrize("mech,x", params)
def test_client_order(mech, x):
    c = ScramClient([mech], USERNAME, PASSWORD)

    with pytest.raises(ScramException):
        c.set_server_first(x['sfirst'])


@pytest.mark.parametrize("mech,x", params)
def test_client(mech, x):
    c = ScramClient([mech], USERNAME, PASSWORD, c_nonce=x['c_nonce'])

    assert c.get_client_first() == x['cfirst']

    c.set_server_first(x['sfirst'])

    assert c.get_client_final() == x['cfinal']


@pytest.mark.parametrize("mech,x", params)
def test_set_client_first(mech, x):
    nonce, user, cfirst_bare = core._set_client_first(
        x['cfirst'], x['s_nonce'])

    assert nonce == x['nonce']
    assert user == USERNAME
    assert cfirst_bare == x['cfirst_bare']


@pytest.mark.parametrize("mech,x", params)
def test_get_server_first(mech, x):
    auth_message, sfirst = core._get_server_first(
        x['nonce'], x['salt'], x['iterations'], x['cfirst_bare'])

    assert auth_message == x['auth_message']
    assert sfirst == x['sfirst']


@pytest.mark.parametrize("mech,x", params)
def test_set_client_final(mech, x):
    server_signature = core._set_client_final(
        x['hf'], x['cfinal'], x['s_nonce'], PASSWORD, x['salt'],
        x['iterations'], x['auth_message'])

    assert server_signature == x['server_signature']


@pytest.mark.parametrize("mech,x", params)
def test_get_server_final(mech, x):
    assert core._get_server_final(x['server_signature']) == x['sfinal']


def password_fn(username):
    lookup = {
        USERNAME: PASSWORD
    }
    return lookup[username]


@pytest.mark.parametrize("mech,x", params)
def test_server_order(mech, x):
    s = ScramServer(password_fn, mechanism=mech)

    with pytest.raises(ScramException):
        s.set_client_final(x['cfinal'])


@pytest.mark.parametrize("mech,x", params)
def test_server(mech, x):
    s = ScramServer(
        password_fn, s_nonce=x['s_nonce'], salt=x['salt'], mechanism=mech)

    s.set_client_first(x['cfirst'])

    assert s.get_server_first() == x['sfirst']

    s.set_client_final(x['cfinal'])

    assert s.get_server_final() == x['sfinal']
