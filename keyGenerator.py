import sys
import logging
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def rtnT():
    seconds = time.time()
    local_time = time.ctime(seconds)
    return local_time

logging.basicConfig(filename='example.log',level=logging.DEBUG)
logging.debug('This message should go to the log file')
logging.info('So should this')
logging.warning('And this, too')

print(len(sys.argv))

if len(sys.argv) == 2:
    print (sys.argv[1])

    # Generate private_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write key to disk 
    # I have choose to use serialization format PKCS8 since TradicionalOpenSSL
    # frequently known as PKCS#1 format is generally considered legacy.
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/

    with open(sys.argv[1]+"_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,    
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    logging.info(rtnT()+": Private Key Generated")
    print ("Your private Key has been created with the following name "+sys.argv[1]+"_private.pem \n and saved on the root of this folder")
    
    #Load Public Key and save
    public_key = private_key.public_key()

    with open(sys.argv[1]+"_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    logging.info(rtnT()+": Public Key Generated")
    print ("Your public Key has been created with the following name "+sys.argv[1]+"_public.pem \n and saved on the root of this folder")

   