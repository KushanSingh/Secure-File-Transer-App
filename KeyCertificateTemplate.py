from genericpath import isfile
from OpenSSL import crypto, SSL
from Utilities import create_directory
import os


# The KeyCertificateTemplate handles the generation of self signed certificates and private and public keys
class KeyCertificateTemplate():
    _private_key_directory_path = os.getcwd() + '/private/'
    public_key_directory_path = os.getcwd() + '/public/'
    cert_directory_path = os.getcwd() + '/certs/'

    def __init__(self, key_name, cert_name):
        self._private_key_path = self._private_key_directory_path + key_name
        self.public_key_path = self.public_key_directory_path + key_name
        self.certificate_path = self.cert_directory_path + cert_name

        # create a key pair
        self.key = crypto.PKey()
        self.key.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed certificate
        self.certificate = crypto.X509()

    def create_certificate(self, common_name, root=None):
        # create the self-signed X509 certificate
        # country name
        self.certificate.get_subject().C = "US"
        # state or province name
        self.certificate.get_subject().ST = "Texas"
        # locality name
        self.certificate.get_subject().L = "Dallas"
        # organization name
        self.certificate.get_subject().O = "UTD"
        # organizational unit name
        self.certificate.get_subject().OU = "ECSS"
        # common name
        self.certificate.get_subject().CN = common_name
        # start time for validity of certificate
        self.certificate.gmtime_adj_notBefore(0)
        # expiry time for validity of certificate
        self.certificate.gmtime_adj_notAfter(365*24*60*60)
        # set public key
        self.certificate.set_pubkey(self.key)

        # set issuer of certificate
        issuer = root.certificate.get_issuer() if root else self.certificate.get_subject()
        self.certificate.set_issuer(issuer)

        # sign the certificate
        key = root.key if root else self.key
        self.certificate.sign(key, 'sha512')

        create_directory(self.cert_directory_path)

        if not os.path.isfile(self.certificate_path):
            with open(self.certificate_path, "w") as certificate_file:
                certificate_file.write(crypto.dump_certificate(
                    crypto.FILETYPE_PEM, self.certificate).decode('utf-8'))

    def create_key_pair(self):
        # create the private and public keys
        create_directory(self._private_key_directory_path)
        create_directory(self.public_key_directory_path)

        public_key = self.certificate.get_pubkey()
        if not os.path.isfile(self.public_key_path):
            with open(self.public_key_path, "w") as public_key_file:
                public_key_file.write(crypto.dump_publickey(
                    crypto.FILETYPE_PEM, public_key).decode('utf-8'))

        if not os.path.isfile(self._private_key_path):
            with open(self._private_key_path, "w") as private_key_file:
                private_key_file.write(crypto.dump_privatekey(
                    crypto.FILETYPE_PEM, self.key).decode('utf-8'))


def generate_keys_and_certs():
    root = KeyCertificateTemplate('root.pem', 'root.crt')
    server = KeyCertificateTemplate('server.pem', 'server.crt')

    root.create_certificate('root')
    root.create_key_pair()

    server.create_certificate('server', root)
    server.create_key_pair()


if __name__ == "__main__":
    generate_keys_and_certs()
