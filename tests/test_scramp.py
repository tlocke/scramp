from scramp import ScramClient
from scramp import core


def test_client_first_message():
    cfmb = core._client_first_message_bare('user', 'rOprNGfwEbeRWgbNEkqO')
    cfm = core._client_first_message(cfmb)
    assert cfm == 'n,,n=user,r=rOprNGfwEbeRWgbNEkqO'


def test_client_final_message():
    server_signature, cfm = core._client_final_message(
        'pencil', 'W22ZaJ0SNY7soEsUEjb6gQ==', 4096,
        'rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0',
        'n=user,r=rOprNGfwEbeRWgbNEkqO',
        'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
        's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096')

    assert server_signature == '6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='

    assert cfm == 'c=biws,' \
        'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,' \
        'p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ='


def test_auth():
    auth = ScramClient(
        ['SCRAM-SHA-256'], 'user', 'pencil', c_nonce='rOprNGfwEbeRWgbNEkqO')

    c = auth.get_client_first_message()
    assert c == 'n,,n=user,r=rOprNGfwEbeRWgbNEkqO'

    auth.set_server_first_message(
        'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
        's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096')

    assert auth.get_client_final_message() == 'c=biws,' \
        'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,' \
        'p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ='
