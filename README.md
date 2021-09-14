# Encrypted-Zip-AES-Project

## zipExtract.py

Since zipfile's password can be brute force. Therefore use AES encryption the pass inside the zip file.

[Advanced Encryption Standard - Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

Use tool pyzipper take out encrypted zip file. \
Then use pycryptodome to take out the Encrypted AES string, with Nonce and Tag to decrypte the Password.

Do not leak your key salt in salt.txt . This is crucially important about the content that was being encrypted in your pass.txt .

### Necessary Packages

- json
- getpass
- pyzipper
- pycryptodome

`pip install pyzipper`
`pip install pycryptodome`

### CLI

zipExtract.py -i <fileName.zip> [-z zipPassword][-e] [-t txtPassword]

### File Hierarchy (which in the zip)

- salt.txt
- pass.txt
