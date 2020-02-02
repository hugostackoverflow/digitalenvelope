from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import cryptography.hazmat.primitives.serialization.base
import sys
import os 
import base64
import logging
import time

def rtnT():
    seconds = time.time()
    local_time = time.ctime(seconds)
    return local_time

logging.basicConfig(filename='example.log',level=logging.INFO)


if len(sys.argv) == 5:
    logging.info(" ")
    logging.info(rtnT()+" ### send.py started ###"+sys.argv[1]+" "+sys.argv[2]+" "+sys.argv[3]+" "+sys.argv[4]+" ")
    _sender = sys.argv[1]
    _receiver = sys.argv[2]
    _ca_cert = sys.argv[3]
    _msg_file = sys.argv[4]

    #-----------------------------------------------------------------------------------------------#
    # 1) The script creates a random Simetric Key and Initialization Vector 
    # 2) The script signe the simetric Key + Inicialization Vector with the Public Key from receiver
    #    The public key is obtain from the receiver crt file and the receiver crt file is verified. 
    # 3) The script now chipher the simetric key + inicialization vector then append the signature. 
    # 4) The script ask for an input messagem, then cipher with the simetric key. 
    #-----------------------------------------------------------------------------------------------#

    #Simple Simetric Key 
    key = os.urandom(32)    #Random Key
    iv = os.urandom(16)     #Random Initialization Vector
    logging.info(rtnT()+": simetric key generated")

    #The Key File will have the Key and the Initialization Vector
    keyInBase64 = base64.urlsafe_b64encode(key+iv)
    with open("key.key", "wb") as key_file:
        key_file.write(keyInBase64)

    #Sign the key file
    with open(_sender+"_private.pem", "rb") as key_file: #Open Private Key from Sender
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            backend=default_backend(),
            password=None
        ) 
    logging.info(rtnT()+": sig key generated")
    signature = private_key.sign(
                    key+iv, #Sing the Key and IV 
                    padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256()
                )
    with open("signature.sig", "wb") as sigFile:
        sigFile.write(signature)
    
    with open(_ca_cert, "rb") as cert_fileCA: #Open CA cert
        issuer_pem_data = cert_fileCA.read()
        
    issuer_cert = x509.load_pem_x509_certificate(issuer_pem_data, default_backend())  
    issuer_public_key = issuer_cert.public_key()

    publicPEM =  issuer_public_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    issuer_public_key = serialization.load_pem_public_key(publicPEM,default_backend())

    with open(_receiver+".crt.pem", "rb") as cert_fileReceiver: #Open Sender CRT
        receiver_pem_data = cert_fileReceiver.read()

    receiver_cert = x509.load_pem_x509_certificate(receiver_pem_data, default_backend())
    receiver_public_key = receiver_cert.public_key()
    receiver_public_key_pem =  receiver_public_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    logging.info(rtnT()+": verify if receiver crt is valid")   
    try:
        logging.info(rtnT()+": receiver crt is valid")
        issuer_public_key.verify(
            receiver_cert.signature,
            receiver_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            receiver_cert.signature_hash_algorithm,
        )

    except:
        logging.warn(rtnT()+": receiver crt is INVALID")




    cipheredKey = receiver_public_key.encrypt(
        key+iv,#Cipher the simetric key + iv
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.info(rtnT()+": key and iv ciphered with public key from receiver")

    #Adding a message with sample text to simulate the full process
    cipher = Cipher(
                    algorithms.AES(key),
                    modes.CTR(iv),
                    backend=default_backend()
                    )
    encryptor = cipher.encryptor()


    #msgS = input("Message: ")
    #msgS = msgS.encode("utf-8")

    with open(_msg_file, "rb") as msg_file: #Open CA cert
        msgS = msg_file.read()

    
    ciferedText = encryptor.update(msgS) + encryptor.finalize()

    logging.info(rtnT()+": cipher message with simetric key")

    with open("Message.txt", "wb") as text_file:
        text_file.write(cipheredKey+signature)
    logging.info(rtnT()+": save cipheredKey and signature to file message.txt")
    with open("secretMessage.txt", "wb") as text_file:
        text_file.write(ciferedText)
    logging.info(rtnT()+": save ciphered msg to file secretMessage.txt")




else:
    print("missing arguments: ie. python3 sende.py sender receiver ca-chain.cert.pem msg.txt ")