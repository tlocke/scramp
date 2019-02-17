# Scramp

A Python implementation of the SCRAM authentication protocol defined by
[RFC 5802](https://tools.ietf.org/html/rfc5802) and
[RFC 7677](https://www.rfc-editor.org/rfc/rfc7677.txt).


## Installation

* Create a virtual environment: `virtualenv --python=python3 venv`
* Activate the virtual environment: `source venv/bin/activate`
* Install: `pip install scramp`


## Usage

Here's an example using both the client and the server. It's a bit contrived as
normally you'd be using either the client or server on its own.

```
>>> from scramp import ScramClient, ScramServer
>>>
>>> USERNAME = 'user'
>>> PASSWORD = 'pencil'
>>> MECHANISMS = ['SCRAM-SHA-256']
>>>
>>> c = ScramClient(MECHANISMS, USERNAME, PASSWORD)
>>>
>>> # Define your own function for getting a password given a username
>>> def password_fn(username):
...     return PASSWORD
>>>
>>> s = ScramServer(password_fn)
>>>
>>> cfirst = c.get_client_first()
>>>
>>> s.set_client_first(cfirst)
>>> sfirst = s.get_server_first()
>>>
>>> c.set_server_first(sfirst)
>>> cfinal = c.get_client_final()
>>>
>>> s.set_client_final(cfinal)
>>> sfinal = s.get_server_final()
>>>
>>> c.set_server_final(sfinal)
>>>
>>> # If it all runs through without raising an exception, the authentication
>>> # has succeeded
```


Here's an example using just the client. The client nonce is specified in order
to give a reproducible example, but in production you'd omit the `c_nonce`
parameter and let `ScramClient` generate a client nonce:

```
>>> from scramp import ScramClient
>>>
>>> USERNAME = 'user'
>>> PASSWORD = 'pencil'
>>> C_NONCE = 'rOprNGfwEbeRWgbNEkqO'
>>> MECHANISMS = ['SCRAM-SHA-256']
>>>
>>> # Normally the c_nonce would be omitted, in which case ScramClient will
>>> # generate the nonce itself.
>>>
>>> c = ScramClient(MECHANISMS, USERNAME, PASSWORD, c_nonce=C_NONCE)
>>>
>>> # Get the client first message and send it to the server
>>> cfirst = c.get_client_first()
>>> print(cfirst)
n,,n=user,r=rOprNGfwEbeRWgbNEkqO
>>>
>>> # Set the first message from the server
>>> c.set_server_first(
...     'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
...     's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096')
>>>
>>> # Get the client final message and send it to the server
>>> cfinal = c.get_client_final()
>>> print(cfinal)
c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
>>>
>>> # Set the final message from the server
>>> c.set_server_final('v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=')
>>>
>>> # If it all runs through without raising an exception, the authentication
>>> # has succeeded
```


Here's an example using just the server. The server nonce and salt is specified
in order to give a reproducible example, but in production you'd omit the
`s_nonce` and `salt` parameters and let `ScramServer` generate them:

```
>>> from scramp import ScramServer
>>>
>>> USERNAME = 'user'
>>> PASSWORD = 'pencil'
>>> S_NONCE = '%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
>>> SALT = 'W22ZaJ0SNY7soEsUEjb6gQ=='
>>>
>>> # Define your own function for getting a password given a username
>>> def password_fn(username):
...     return PASSWORD
>>>
>>> # Normally the c_nonce parameter would be omitted, in which case
>>> # ScramClient will generate the nonce itself.
>>>
>>> s = ScramServer(password_fn, s_nonce=S_NONCE, salt=SALT)
>>>
>>> # Set the first message from the client
>>> s.set_client_first('n,,n=user,r=rOprNGfwEbeRWgbNEkqO')
>>>
>>> # Get the first server message, and send it to the client
>>> sfirst = s.get_server_first()
>>> print(sfirst)
r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096
>>>
>>> # Set the final message from the client
>>> s.set_client_final(
...     'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
...     'p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=')
>>>
>>> # Get the final server message and send it to the client
>>> sfinal = s.get_server_final()
>>> print(sfinal)
v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=
>>>
>>> # If it all runs through without raising an exception, the authentication
>>> # has succeeded
```


## Testing

* Activate the virtual environment: `source venv/bin/activate`
* Install `tox`: `pip install tox`
* Run `tox`: `tox`


## Doing A Release Of Scramp

Run `tox` to make sure all tests pass, then update the release notes, then do:

```
git tag -a x.y.z -m "version x.y.z"
rm -r dist
python setup.py sdist bdist_wheel --python-tag py3
for f in dist/*; do gpg --detach-sign -a $f; done
twine upload dist/*
```


## Release Notes


### Version 1.0.0, 2019-02-17

* Implement the server side as well as the client side.


### Version 0.0.0, 2019-02-10

* Copied SCRAM implementation from [pg8000](https://github.com/tlocke/pg8000).
  The idea is to make it a general SCRAM implemtation. Credit to the
  [Scrampy](https://github.com/cagdass/scrampy) project which I read through to
  help with this project. Also credit to the
  [passlib](https://github.com/efficks/passlib) project from which I copied the
  `saslprep` function.
