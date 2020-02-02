# My digital envelope

The project includes the following scripts:
- send.py 
-- send.py file is responsible to send the message to receiver
- receive.py 
-- receive.py file is responsible to receive the message from sender
- csrGenerator.py
-- generate csr for CA
- keyGenerator.py
-- generate private and public key
I have used the python library https://cryptography.io/ and OpenSSL to create the ROOT CA
```bash
 pip install cryptography
 brew install openssl
```
To create the root ca and intermediate I have followed the recipe from:
```bash
Google Search: create root ca and intermediate using openssl
https://jamielinux.com/docs/openssl-certificate-authority/create-the-intermediate-pair.html
```
## Overview
Create private and public keys and create csr file
![alt text](https://i.imgur.com/C7yHV1x.png)

Validate CSR with CA
![alt text](https://i.imgur.com/7XnW1S6.png)

Send and Receive
![alt text](https://i.imgur.com/rksiYmm.png)
- all public keys used are validated against the CA. The validation is basic and I could also validate the sender/receiver NameOID.COMMON_NAME



## Usage
* Create sender private and public key
```bash
python3 keyGenerator.py sender
```
* Create receiver private and public key
```bash
python3 keyGenerator.py receiver
```
* Create csr file for sender
```bash
python3 csrGenerator.py sender
```
* Create csr file for receiver
```bash
python3 csrGenerator.py receiver
```
* Create crt file for sender
```bash
openssl ca -config intermediate/openssl.cnf \ 
    -extensions server_cert -days 375 -notext -md sha256 \
    -in senderCsr.pem \
    -out sender.crt.pem
Enter pwd: "Braga.2020"
```

* Create crt file for sender
```bash
openssl ca -config intermediate/openssl.cnf \ 
    -extensions server_cert -days 375 -notext -md sha256 \
    -in receiverCsr.pem \
    -out receiver.crt.pem
Enter pwd: "Braga.2020"
```

* Send Message
```bash
python3 send.py sender receiver ca-chain.cert.pem msg.txt
```
* Send log's
```bash
cat example.log
INFO:root:Sun Feb  2 17:27:23 2020 ### send.py started ###sender receiver ca-chain.cert.pem msg.txt 
INFO:root:Sun Feb  2 17:27:23 2020: simetric key generated
INFO:root:Sun Feb  2 17:27:23 2020: sig key generated
INFO:root:Sun Feb  2 17:27:23 2020: verify if receiver crt is valid
INFO:root:Sun Feb  2 17:27:23 2020: receiver crt is valid
INFO:root:Sun Feb  2 17:27:23 2020: key and iv ciphered with public key from receiver
INFO:root:Sun Feb  2 17:27:23 2020: cipher message with simetric key
INFO:root:Sun Feb  2 17:27:23 2020: save cipheredKey and signature to file message.txt
INFO:root:Sun Feb  2 17:27:23 2020: save ciphered msg to file secretMessage.txt
```
* Receive Message
```bash
python3 receive.py sender receiver ca-chain.cert.pem signature.sig Message.txt secretMessage.txt
```
* Receive log's
```bash
cat example.log
INFO:root:Sun Feb  2 18:12:29 2020 ### receive.py started ###sender receiver ca-chain.cert.pem signature.sig Message.txt secretMessage.txt
INFO:root:Sun Feb  2 18:12:29 2020: load CA cert
INFO:root:Sun Feb  2 18:12:29 2020: load receiver private key
INFO:root:Sun Feb  2 18:12:29 2020: load Message.txt
INFO:root:Sun Feb  2 18:12:29 2020: load sender cert
INFO:root:Sun Feb  2 18:12:29 2020: try to validate cert from sender with CA cert
INFO:root:Sun Feb  2 18:12:29 2020: valid cert from sender
INFO:root:Sun Feb  2 18:12:29 2020: decrypt envelope with private key from receiver
INFO:root:Sun Feb  2 18:12:29 2020: will try to validate signature
INFO:root:Sun Feb  2 18:12:29 2020: signature validated
```
