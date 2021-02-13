import hashlib

import pytest

from scramp import ScramClient, ScramException, ScramMechanism, core
from scramp.utils import b64dec

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
    'hf': hashlib.sha1,
    'stored_key': '6dlGYMOdZcOPutkcNY8U2g7vK9Y=',
    'server_key': 'D+CSWLOshSulAsxiupA+qs2/fTE=',
    'use_binding': False,
    'cbind_data': None,
    'channel_binding': None,
}

SCRAM_SHA_1_PLUS_EXCHANGE = {
    'cfirst': 'p=tls-unique,,n=user,r=fyko+d2lbbFgONRv9qkxdawL',
    'sfirst': 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,'
    's=QSXCR+Q6sek8bf92,i=4096',
    'cfinal': 'c=cD10bHMtdW5pcXVlLCx4eHg=,'
    'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,'
    'p=/63TtbB5lIS6610+k4/luJMJqAI=',
    'sfinal': 'v=GCPHy5gy1sRwXTCbwNhiiWIzLtU=',
    'cfirst_bare': 'n=user,r=fyko+d2lbbFgONRv9qkxdawL',
    'c_nonce': 'fyko+d2lbbFgONRv9qkxdawL',
    's_nonce': '3rfcNHYJY1ZVvWVs7j',
    'nonce': 'fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j',
    'auth_message': 'n=user,r=fyko+d2lbbFgONRv9qkxdawL,'
    'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,'
    's=QSXCR+Q6sek8bf92,i=4096,c=cD10bHMtdW5pcXVlLCx4eHg=,'
    'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j',
    'salt': 'QSXCR+Q6sek8bf92',
    'iterations': 4096,
    'server_signature': 'GCPHy5gy1sRwXTCbwNhiiWIzLtU=',
    'hf': hashlib.sha1,
    'stored_key': '6dlGYMOdZcOPutkcNY8U2g7vK9Y=',
    'server_key': 'D+CSWLOshSulAsxiupA+qs2/fTE=',
    'use_binding': True,
    'cbind_data': b'xxx',
    'channel_binding': ('tls-unique', b'xxx'),
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
    'hf': hashlib.sha256,
    'stored_key': 'WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=',
    'server_key': 'wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=',
    'use_binding': False,
    'cbind_data': None,
    'channel_binding': None,
}

SCRAM_SHA_256_PLUS_EXCHANGE = {
    'cfirst': 'p=tls-unique,,n=user,r=rOprNGfwEbeRWgbNEkqO',
    'sfirst': 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
    's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096',
    'cfinal': 'c=cD10bHMtdW5pcXVlLCx4eHg=,'
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
    'p=v0J7PaQUPWowoTrwRLCKLzIZBpNUhWFlTrUKI1j9DpM=',
    'sfinal': 'v=XjAev9iHBOvTxT+eNzBaFmP1IrqWah2PpZAa0wQrfY4=',
    'cfirst_bare': 'n=user,r=rOprNGfwEbeRWgbNEkqO',
    'c_nonce': 'rOprNGfwEbeRWgbNEkqO',
    's_nonce': '%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
    'nonce': 'rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
    'auth_message': 'n=user,r=rOprNGfwEbeRWgbNEkqO,'
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
    's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=cD10bHMtdW5pcXVlLCx4eHg=,'
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
    'salt': 'W22ZaJ0SNY7soEsUEjb6gQ==',
    'iterations': 4096,
    'server_signature': 'XjAev9iHBOvTxT+eNzBaFmP1IrqWah2PpZAa0wQrfY4=',
    'hf': hashlib.sha256,
    'stored_key': 'WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=',
    'server_key': 'wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=',
    'use_binding': True,
    'cbind_data': b'xxx',
    'channel_binding': ('tls-unique', b'xxx'),
}

params = [
    ('SCRAM-SHA-1', SCRAM_SHA_1_EXCHANGE),
    ('SCRAM-SHA-1-PLUS', SCRAM_SHA_1_PLUS_EXCHANGE),
    ('SCRAM-SHA-256', SCRAM_SHA_256_EXCHANGE),
    ('SCRAM-SHA-256-PLUS', SCRAM_SHA_256_PLUS_EXCHANGE),
]


@pytest.mark.parametrize("mech,x", params)
def test_get_client_first(mech, x):
    cfirst_bare, cfirst = core._get_client_first(
        USERNAME, x['c_nonce'], x['channel_binding'])

    assert cfirst_bare == x['cfirst_bare']
    assert cfirst == x['cfirst']


@pytest.mark.parametrize("mech,x", params)
def test_make_auth_message(mech, x):
    auth_msg = core._make_auth_message(
        x['nonce'], x['cfirst_bare'], x['sfirst'], x['channel_binding'])
    assert auth_msg == x['auth_message']


@pytest.mark.parametrize("mech,x", params)
def test_get_client_final(mech, x):
    server_signature, cfinal = core._get_client_final(
        x['hf'], PASSWORD, x['salt'], x['iterations'], x['nonce'],
        x['auth_message'], x['channel_binding'])

    assert server_signature == x['server_signature']
    assert cfinal == x['cfinal']


@pytest.mark.parametrize("mech,x", params)
def test_client_order(mech, x):
    c = ScramClient(
        [mech], USERNAME, PASSWORD, channel_binding=x['channel_binding'])

    with pytest.raises(ScramException):
        c.set_server_first(x['sfirst'])


@pytest.mark.parametrize("mech,x", params)
def test_client(mech, x):
    c = ScramClient(
        [mech], USERNAME, PASSWORD, channel_binding=x['channel_binding'],
        c_nonce=x['c_nonce'])

    assert c.get_client_first() == x['cfirst']

    c.set_server_first(x['sfirst'])

    assert c.get_client_final() == x['cfinal']


@pytest.mark.parametrize("mech,x", params)
def test_set_client_first(mech, x):
    nonce, user, cfirst_bare = core._set_client_first(
        x['cfirst'], x['s_nonce'], x['channel_binding'])

    assert nonce == x['nonce']
    assert user == USERNAME
    assert cfirst_bare == x['cfirst_bare']


@pytest.mark.parametrize("mech,x", params)
def test_get_server_first(mech, x):
    auth_message, sfirst = core._get_server_first(
        x['nonce'], x['salt'], x['iterations'], x['cfirst_bare'],
        x['channel_binding'])

    assert auth_message == x['auth_message']
    assert sfirst == x['sfirst']


@pytest.mark.parametrize("mech,x", params)
def test_set_client_final(mech, x):
    server_signature = core._set_client_final(
        x['hf'], x['cfinal'], x['s_nonce'], b64dec(x['stored_key']),
        b64dec(x['server_key']), x['auth_message'], x['channel_binding'])

    assert server_signature == x['server_signature']


@pytest.mark.parametrize("mech,x", params)
def test_get_server_final(mech, x):
    assert core._get_server_final(x['server_signature']) == x['sfinal']


@pytest.mark.parametrize("mech,x", params)
def test_server_order(mech, x):
    m = ScramMechanism(mechanism=mech)

    def auth_fn(username):
        lookup = {
            USERNAME: m.make_auth_info(
                PASSWORD, salt=x['salt'], iteration_count=x['iterations'])
        }
        return lookup[username]

    s = m.make_server(auth_fn, channel_binding=x['channel_binding'])

    with pytest.raises(ScramException):
        s.set_client_final(x['cfinal'])


@pytest.mark.parametrize("mech,x", params)
def test_server(mech, x):
    m = ScramMechanism(mechanism=mech)

    def auth_fn(username):
        lookup = {
            USERNAME: m.make_auth_info(
                PASSWORD, salt=b64dec(x['salt']),
                iteration_count=x['iterations'])
        }
        return lookup[username]

    s = m.make_server(
        auth_fn, channel_binding=x['channel_binding'], s_nonce=x['s_nonce'])

    s.set_client_first(x['cfirst'])

    assert s.get_server_first() == x['sfirst']

    s.set_client_final(x['cfinal'])

    assert s.get_server_final() == x['sfinal']
