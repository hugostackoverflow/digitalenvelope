#CA done https://gist.github.com/Soarez/9688998

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import base64
import sys

if len(sys.argv) == 2:
    print (sys.argv[1])
    myclient = sys.argv[1]
    with open(myclient+"_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
    )
    builder = x509.CertificateSigningRequestBuilder()

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u""+myclient+'.io'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Minho"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braga"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u""+myclient+" Lda"),
        ]))


    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )



    request = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    print(request)
    print(isinstance(request, x509.CertificateSigningRequest))

    with open(myclient+"Csr.pem", "wb") as f:
            f.write(request.public_bytes(serialization.Encoding.PEM))



######## Documentation ###############
# After creating the CSR the CA needs to create the certificate.
# # cd /root/ca
# openssl ca -config intermediate/openssl.cnf \ 
#    -extensions server_cert -days 375 -notext -md sha256 \
#    -in /Users/hugo/Trabalho Pratico Crypto/Crypto2020/TODO/Final/receiverCsr.pem \
#    -out /Users/hugo/Trabalho Pratico Crypto/Crypto2020/TODO/Final/receiver.crt.pem
# chmod 444 intermediate/certs/www.example.com.cert.pem
#
#
