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



if len(sys.argv) == 7:
    logging.info(" ")
    logging.info(rtnT()+" ### receive.py started ###"+sys.argv[1]+" "+sys.argv[2]+" "+sys.argv[3]+" "+sys.argv[4]+" "+sys.argv[5]+" "+sys.argv[6])
    _sender = sys.argv[1]
    _receiver = sys.argv[2]
    _ca_cert = sys.argv[3]
    _sig_file = sys.argv[4]
    _key_file = sys.argv[5]
    _msg_file = sys.argv[6]

    #Load Intermediate CA
    with open(_ca_cert, "rb") as cert_fileCA: #Open Cert from CA Intermediate
                ca_int_pem_data = cert_fileCA.read()
    ca_int_cert = x509.load_pem_x509_certificate(ca_int_pem_data, default_backend())#Load
    logging.info(rtnT()+": load CA cert")         
    #Load Intermediate CA Public Key
    ca_int_public_key = ca_int_cert.public_key()

    ca_int_public_key_pem =  ca_int_public_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)   
    #print(publicPEM)

    #Load Private Key:
    with open(_receiver+"_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
    )
    logging.info(rtnT()+": load receiver private key")  
    #Load Message.txt file:
    with open(_key_file, "rb") as text_file:
        keyIvSig=text_file.read()
    logging.info(rtnT()+": load "+_key_file)  

    keyIv = keyIvSig[0:256] #key and iv cifered with the public key of receiver

    sig = keyIvSig[256:512] #Signature of the key and iv plain 

    #Load Sender CRT and Public Key
    with open(_sender+".crt.pem", "rb") as cert_fileSender: #Open Sender CRT
            sender_pem_data = cert_fileSender.read()
    logging.info(rtnT()+": load sender cert")  

    sender_cert = x509.load_pem_x509_certificate(sender_pem_data, default_backend())
    sender_public_key = sender_cert.public_key()

    sender_public_key_pem =  sender_public_key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)   


    #Verify Auth 
    cert_to_check = x509.load_pem_x509_certificate(sender_pem_data, default_backend()) #Load Sender CRT
    issuer_public_key = serialization.load_pem_public_key(ca_int_public_key_pem,default_backend())
    logging.info(rtnT()+": try to validate cert from sender with CA cert")  
    try:
        issuer_public_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_check.signature_hash_algorithm,
            )
        logging.info(rtnT()+": valid cert from sender")  
    except:
        logging.info(rtnT()+": invalid cert from sender!!")  

    #Decrypt
    envelope = private_key.decrypt(
                keyIv,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                ) 
            )
    logging.info(rtnT()+": decrypt envelope with private key from receiver")  
    key = envelope[0:32] #The key exchanged
    iv = envelope[32:48] #The initialization vector exchanged



    #Verify Signature
    logging.info(rtnT()+": will try to validate signature")  
    try:
        sender_public_key.verify(
            sig,
            envelope,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logging.info(rtnT()+": signature validated")  
    except:
        logging.info(rtnT()+": invalide signature")  
    
    #Decifer the message

    with open(_msg_file, "rb") as text_file:
            msg = text_file.read()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    
    decryptor = cipher.decryptor()
    msg = decryptor.update(msg) + decryptor.finalize()
    msg=msg.decode("utf-8")
    print(msg)
    logging.info(rtnT()+": message decifer "+msg)  
    
else:
    print("missing arguments: i.e python3 receive.py sender receiver ca-chain.cert signature.sig Message.txt secretMessage.txt")

