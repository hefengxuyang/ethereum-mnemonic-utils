Ethereum Mnemonic Key Utils
================================

Script to convert Ethereum mnemonic keys into regular private keys that can be consumed by regular wallets. Default parameters work for Ledger ETH wallets, but it *should* be able to support any wallet that uses BIP32 HD and BIP39 seed standards.

Modularity and extensibility were sacrificed to keep the code as simple and linear as possible. That way it should much easier for you to review this before running it :)

Logic adapted from https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py and https://github.com/trezor/python-mnemonic.

### Requirements

python3 with version <=3.8.7  (the latest version is unsupported, you can use pyenv when the system contain another python)

```sh
pip install -r requirements.txt
```

### Examples

#### Mnemonic key > private key
```sh
	$ echo "legal winner thank year wave sausage worth useful legal winner thank yellow" > myfile
    $ ./mnemonic_utils.py myfile
```