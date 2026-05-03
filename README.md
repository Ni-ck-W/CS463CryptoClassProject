# CS463CryptoClassProject
## Overview
This will be a cli program that can provide encryption and decryption of AES. Using this AES functionality the user will have the following options:
1) Type single plaintext/encoded text to convert in the terminal
2) Selecting a file to encrypt/decrypt the entire file
3) Selecting a file to encrypt/decrypt a list of text on a file

## Dependencies
### Requires OpenSSL dev headers:
#### Debian/Ubuntu
sudo apt install libssl-dev
#### Fedora
sudo dnf install openssl-devel
## Building
Run: `g++ -o aescli aescli.cpp -lssl -lcrypto`
## Running
1. chmod +x aescli
2. ./aescli -help
