from OpenSSL import crypto
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# The AsymmetricCryptobox handles all public-key cryptographic operations
# A new AsymmetricCryptobox should be generated for each communication session
class AsymmetricCryptobox():
    def __init__(self,
                 path_to_remote_party_certificate: str = None,
                 path_to_remote_public_key: str = None,
                 path_to_local_party_private_key: str = None,
                 path_to_root_certificate: str = None):

        self.certificate = None
        self.remote_public_key = None
        self.private_key = None
        self.path_to_root_certificate = path_to_root_certificate

        # load the certificate of the remote party if given
        if path_to_remote_party_certificate:
            with open(path_to_remote_party_certificate, 'rt') as certificate_file:
                self.certificate = crypto.load_certificate(
                    crypto.FILETYPE_PEM, certificate_file.read())

        # load the public key of the remote party if given
        if path_to_remote_public_key:
            with open(path_to_remote_public_key, 'rt') as remote_public_key_file:
                self.remote_public_key = RSA.import_key(remote_public_key_file.read())

        # load the private key of the local party if given
        if path_to_local_party_private_key:
            with open(path_to_local_party_private_key, 'rt') as private_key_file:
                self.private_key = RSA.import_key(private_key_file.read())

    def verify_certificate(self) -> bool:
        if not self.path_to_root_certificate:
            return False

        with open(self.path_to_root_certificate, 'rt') as root_certificate_file:
            root_certificate = crypto.load_certificate(
                crypto.FILETYPE_PEM, root_certificate_file.read())

            store = crypto.X509Store()
            store.add_cert(root_certificate)

            context = crypto.X509StoreContext(store, self.certificate)

            try:
                context.verify_certificate()
                # If no validation error was thrown, the certificate is valid
                return True
            except crypto.X509StoreContextError:
                return False

    def encrypt(self, message: bytes):
        # get public key from self.remote_public_key
        # encrypt message with public key using library function
        rsa_cipher = PKCS1_OAEP.new(self.remote_public_key)
        ciphertext = rsa_cipher.encrypt(message)
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        # get private key from self.private_key
        # decrypt message with private key using library function
        rsa_cipher = PKCS1_OAEP.new(self.private_key)
        message = rsa_cipher.decrypt(ciphertext)
        return message

if __name__ == "__main__":
    client = AsymmetricCryptobox('certs/server.crt', 'public/server.pem', None, 'certs/root.crt')
    server = AsymmetricCryptobox(None, None, 'private/server.pem', None)

    # verify server certificate
    if client.verify_certificate():
        print('Successfully validated server!\n')
        message = b's3c3rt m5g'
        print(f'encrypting {message}')
        # encrypt message with the server public key
        ciphertext = client.encrypt(message)
        print(f'ciphertext = {ciphertext}')
        print(f'len(ciphertext) = {len(ciphertext)}')
        # decrypt ciphertext with the server private key
        decrypted_message = server.decrypt(ciphertext)
        print(f'decrypted_message = {decrypted_message}')

        if message == decrypted_message: print('Success!')
    else:
        print('Error: Could not verify server')
