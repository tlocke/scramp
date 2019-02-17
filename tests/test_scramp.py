from scramp import ScramClient, ScramServer, ScramException
from scramp import core
import pytest

CFIRST = 'n,,n=user,r=rOprNGfwEbeRWgbNEkqO'
SFIRST = 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,' \
    's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
CFINAL = 'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,' \
    'p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ='
SFINAL = 'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='
CFIRST_BARE = 'n=user,r=rOprNGfwEbeRWgbNEkqO'
C_NONCE = 'rOprNGfwEbeRWgbNEkqO'
S_NONCE = '%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
USERNAME = 'user'
NONCE = 'rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
AUTH_MESSAGE = 'n=user,r=rOprNGfwEbeRWgbNEkqO,' \
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,' \
    's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,' \
    'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
PASSWORD = 'pencil'
SALT = 'W22ZaJ0SNY7soEsUEjb6gQ=='
ITERATIONS = 4096
SERVER_SIGNATURE = '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='


def test_get_client_first():
    cfirst_bare, cfirst = core._get_client_first(USERNAME, C_NONCE)
    assert cfirst_bare == CFIRST_BARE
    assert cfirst == CFIRST


def test_make_auth_message():
    auth_msg = core._make_auth_message(NONCE, CFIRST_BARE, SFIRST)
    assert auth_msg == AUTH_MESSAGE


def test_get_client_final():
    server_signature, cfinal = core._get_client_final(
        PASSWORD, SALT, ITERATIONS, NONCE, AUTH_MESSAGE)

    assert server_signature == SERVER_SIGNATURE
    assert cfinal == CFINAL


def test_client_order():
    c = ScramClient(['SCRAM-SHA-256'], USERNAME, PASSWORD)

    with pytest.raises(ScramException):
        c.set_server_first(SFIRST)


def test_client():
    c = ScramClient(['SCRAM-SHA-256'], USERNAME, PASSWORD, c_nonce=C_NONCE)

    assert c.get_client_first() == CFIRST

    c.set_server_first(SFIRST)

    assert c.get_client_final() == CFINAL


def test_set_client_first():
    nonce, user, cfirst_bare = core._set_client_first(CFIRST, S_NONCE)

    assert nonce == NONCE
    assert user == USERNAME
    assert cfirst_bare == CFIRST_BARE


def test_get_server_first():
    auth_message, sfirst = core._get_server_first(
        NONCE, SALT, ITERATIONS, CFIRST_BARE)

    assert auth_message == AUTH_MESSAGE
    assert sfirst == SFIRST


def test_set_client_final():
    server_signature = core._set_client_final(
        CFINAL, S_NONCE, PASSWORD, SALT, ITERATIONS, AUTH_MESSAGE)

    assert server_signature == SERVER_SIGNATURE


def test_get_server_final():
    assert core._get_server_final(SERVER_SIGNATURE) == SFINAL


def password_fn(username):
    lookup = {
        USERNAME: PASSWORD
    }
    return lookup[username]


def test_server_order():
    s = ScramServer(password_fn)

    with pytest.raises(ScramException):
        s.set_client_final(CFINAL)


def test_server():
    s = ScramServer(password_fn, s_nonce=S_NONCE, salt=SALT)

    s.set_client_first(CFIRST)

    assert s.get_server_first() == SFIRST

    s.set_client_final(CFINAL)

    assert s.get_server_final() == SFINAL
