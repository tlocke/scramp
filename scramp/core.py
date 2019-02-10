import hmac
from uuid import uuid4
from base64 import b64encode, b64decode
import hashlib
from stringprep import (
    in_table_a1, in_table_b1, in_table_c21_c22, in_table_c3, in_table_c4,
    in_table_c5, in_table_c6, in_table_c7, in_table_c8, in_table_c9,
    in_table_c12, in_table_d1, in_table_d2)
import unicodedata


# https://tools.ietf.org/html/rfc5802
# https://www.rfc-editor.org/rfc/rfc7677.txt

class ScramClient():
    def __init__(self, mechanisms, username, password, c_nonce=None):
        if 'SCRAM-SHA-256' not in mechanisms:
            raise Exception(
                "The only recognized mechanism is SCRAM-SHA-256, and this "
                "can't be found in " + mechanisms + ".")
        self.mechanisms = mechanisms
        if c_nonce is None:
            self.c_nonce = _make_nonce()
        else:
            self.c_nonce = c_nonce
        self.username = username
        self.password = password

    def get_client_first_message(self):
        self.client_first_message_bare = _client_first_message_bare(
            self.username, self.c_nonce)
        return _client_first_message(self.client_first_message_bare)

    def set_server_first_message(self, message):
        self.server_first_message = message
        msg = _parse_message(message)
        self.nonce = msg['r']
        self.salt = msg['s']
        self.iterations = int(msg['i'])

        if not self.nonce.startswith(self.c_nonce):
            raise Exception("Client nonce doesn't match.")

    def get_client_final_message(self):
        server_signature, cfm = _client_final_message(
            self.password, self.salt, self.iterations, self.nonce,
            self.client_first_message_bare, self.server_first_message)

        self.server_signature = server_signature
        return cfm

    def set_server_final_message(self, message):
        msg = _parse_message(message)
        if self.server_signature != msg['v']:
            raise Exception("The server signature doesn't match.")


'''
Here's an example using both the client and the server. It's a bit contrived as
normally you'd be using either the client or server on their own.

```
>>> from scramp import ScramClient, ScramServer
>>>
>>> username = 'user'
>>> password = 'pencil'
>>>
>>> c = ScramClient(['SCRAM-SHA-256'], username, password)
>>> s = ScramServer(['SCRAM-SHA-256'], username, password)
>>>
>>> cfirst = c.get_client_first_message()
>>>
>>> sfirst = s.set_client_first_message(cfirst)
>>>
>>> cfinal = c.set_server_first_message(sfirst)
>>>
>>> sfinal = s.set_client_final_message(cfinal)
>>>
>>> c.set_server_final_message(sfinal)
>>>
>>> # If it all runs through without raising an exception, the authentication
>>> # has succeeded
```


class ScramServer():
    def __init__(
            self, mechanisms, password_lookup, s_nonce=None, iterations=4096):
        if 'SCRAM-SHA-256' not in mechanisms:
            raise Exception(
                "The only recognized mechanism is SCRAM-SHA-256, and this "
                "can't be found in " + mechanisms + ".")
        self.mechanisms = mechanisms
        if s_nonce is None:
            self.s_nonce = _make_nonce()
        else:
            self.s_nonce = s_nonce
        self.salt = _b64encode(urandom(16))
        self.password_lookup = password_lookup
        self.iterations = iterations

    def set_client_first_message(self, message):
        msg = _parse_message(message)
        c_nonce = msg['r']
        nonce = c_nonce + self.s_nonce
        self.user = msg['n']
        return _server_first_message(nonce, self.salt, self.iterations)

    def set_client_final_message(self, message):
        msg = _parse_message(message)
        self.nonce = msg['r']
        self.salt = msg['s']
        self.iterations = int(msg['i'])

        return _set_client_final_message(
            msg['r'], self.s_nonce, self.iterations, msg['p'])
        if not self.nonce.startswith(self.c_nonce):
            raise Exception("Client nonce doesn't match.")

    def get_client_final_message(self):
        server_signature, cfm = _client_final_message(
            self.password, self.salt, self.iterations, self.nonce,
            self.client_first_message_bare, self.server_first_message)

        self.server_signature = server_signature
        return cfm

    def set_server_final_message(self, message):
        msg = _parse_message(message)
        if self.server_signature != msg['v']:
            raise Exception("The server signature doesn't match.")
'''


def _make_nonce():
    return str(uuid4()).replace('-', '')


def _hmac(key, msg):
    return hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()


def _h(msg):
    return hashlib.sha256(msg).digest()


def _hi(password, salt, iterations):
    u = ui = _hmac(password, salt + b'\x00\x00\x00\x01')
    for i in range(iterations - 1):
        ui = _hmac(password, ui)
        u = _xor(u, ui)
    return u


def hi_iter(password, mac, iterations):
    if iterations == 0:
        return mac
    else:
        new_mac = _hmac(password, mac)
        return _xor(hi_iter(password, new_mac, iterations-1), mac)


def _parse_message(msg):
    return dict((e[0], e[2:]) for e in msg.split(',') if e[1] == '=')


def _client_first_message_bare(username, c_nonce):
    return ','.join(('n=' + saslprep(username), 'r=' + c_nonce))


def _client_first_message(client_first_message_bare):
    return 'n,,' + client_first_message_bare


def _b64enc(binary):
    return b64encode(binary).decode('utf8')


def _b64dec(string):
    return b64decode(string)


def _uenc(string):
    return string.encode('utf-8')


def _xor(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))


def _client_final_message(
        password, salt, iterations, nonce, client_first_message_bare,
        server_first_message):

    salted_password = _hi(_uenc(saslprep(password)), _b64dec(salt), iterations)
    client_key = _hmac(salted_password, b"Client Key")
    stored_key = _h(client_key)

    message = ['c=' + _b64enc(b'n,,'), 'r=' + nonce]

    auth_message = ','.join(
        (client_first_message_bare, server_first_message, ','.join(message)))

    client_signature = _hmac(stored_key, _uenc(auth_message))
    client_proof = _xor(client_key, client_signature)
    server_key = _hmac(salted_password, b"Server Key")
    server_signature = _hmac(server_key, _uenc(auth_message))

    message.append('p=' + _b64enc(client_proof))
    return _b64enc(server_signature), ','.join(message)


'''
def _server_first_message(nonce, salt, iterations):
    return ','.join(('r=' + nonce, 's=' + salt, 'i=' + str(iterations)))


def _set_client_final_message(nonce, s_nonce, iterations, proof, passoword):
    if not nonce.startswith(s_nonce):
        raise Exception("Client nonce doesn't match.")

    salted_password = _hi(_uenc(saslprep(password)), _b64dec(salt), iterations)
    client_key = _hmac(salted_password, b"Client Key")
    stored_key = _h(client_key)

    message = ['c=' + _b64enc(b'n,,'), 'r=' + nonce]

    auth_message = ','.join(
        (client_first_message_bare, server_first_message, ','.join(message)))

    client_signature = _hmac(stored_key, _uenc(auth_message))
    client_proof = _xor(client_key, client_signature)
    server_key = _hmac(salted_password, b"Server Key")
    server_signature = _hmac(server_key, _uenc(auth_message))

    message.append('p=' + _b64enc(client_proof))
    return _b64enc(server_signature), ','.join(message)
'''


def saslprep(source):
    # mapping stage
    #   - map non-ascii spaces to U+0020 (stringprep C.1.2)
    #   - strip 'commonly mapped to nothing' chars (stringprep B.1)
    data = ''.join(
        ' ' if in_table_c12(c) else c for c in source if not in_table_b1(c))

    # normalize to KC form
    data = unicodedata.normalize('NFKC', data)
    if not data:
        return ''

    # check for invalid bi-directional strings.
    # stringprep requires the following:
    #   - chars in C.8 must be prohibited.
    #   - if any R/AL chars in string:
    #       - no L chars allowed in string
    #       - first and last must be R/AL chars
    # this checks if start/end are R/AL chars. if so, prohibited loop
    # will forbid all L chars. if not, prohibited loop will forbid all
    # R/AL chars instead. in both cases, prohibited loop takes care of C.8.
    is_ral_char = in_table_d1
    if is_ral_char(data[0]):
        if not is_ral_char(data[-1]):
            raise ValueError("malformed bidi sequence")
        # forbid L chars within R/AL sequence.
        is_forbidden_bidi_char = in_table_d2
    else:
        # forbid R/AL chars if start not setup correctly; L chars allowed.
        is_forbidden_bidi_char = is_ral_char

    # check for prohibited output
    # stringprep tables A.1, B.1, C.1.2, C.2 - C.9
    for c in data:
        # check for chars mapping stage should have removed
        assert not in_table_b1(c), "failed to strip B.1 in mapping stage"
        assert not in_table_c12(c), "failed to replace C.1.2 in mapping stage"

        # check for forbidden chars
        for f, msg in (
                (in_table_a1, "unassigned code points forbidden"),
                (in_table_c21_c22, "control characters forbidden"),
                (in_table_c3, "private use characters forbidden"),
                (in_table_c4, "non-char code points forbidden"),
                (in_table_c5, "surrogate codes forbidden"),
                (in_table_c6, "non-plaintext chars forbidden"),
                (in_table_c7, "non-canonical chars forbidden"),
                (in_table_c8, "display-modifying/deprecated chars forbidden"),
                (in_table_c9, "tagged characters forbidden"),
                (is_forbidden_bidi_char, "forbidden bidi character")):
            if f(c):
                raise ValueError(msg)

    return data
