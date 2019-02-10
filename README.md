# Scramp

A Python implementation of the SCRAM protocol.


## Installation

* Create a virtual environment: `virtualenv --python=python3 venv`
* Activate the virtual environment: `source venv/bin/activate`
* Install: `pip install scramp`


## Usage

Here's an example using both the client and the server. It's a bit contrived as
the client nonce is specified in order to give a reproducible example:

```
>>> from scramp import ScramClient
>>>
>>> username = 'user'
>>> password = 'pencil'
>>> c_nonce = 'rOprNGfwEbeRWgbNEkqO'
>>> mechanisms = ['SCRAM-SHA-256']
>>>
>>> # Normally the c_nonce would be omitted, in which case ScramClient will
>>> # generate the nonce itself.
>>>
>>> c = ScramClient(mechanisms, username, password, c_nonce=c_nonce)
>>> cfirst = c.get_client_first_message()
>>> print(cfirst)
n,,n=user,r=rOprNGfwEbeRWgbNEkqO
>>>
>>> # Send cfirst to the server, and get back sfirst
>>> sfirst = 'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,' + \
...     's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
>>> 
>>> c.set_server_first_message(sfirst)
>>>
>>> cfinal = c.get_client_final_message()
>>> print(cfinal)
c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
>>>
>>> # Send cfinal to the server, and get back sfinal
>>> sfinal = 'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='
>>> 
>>> c.set_server_final_message(sfinal)
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


### Version 0.0.0, 2019-02-10

* Copied SCRAM implementation from https://github.com/tlocke/pg8000[pg8000].
  The idea is to make it a general SCRAM implemtation. Credit to the
  https://github.com/cagdass/scrampy[Scrampy] project which I read through to
  help with this project. Also credit to the
  https://github.com/efficks/passlib[passlib] project from which I copied the
  `saslprep` function.
