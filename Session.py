from SymmetricCryptobox import SymmetricCryptobox
import time

# SHA256 results in 32 byte output
HMAC_LENGTH = 32
# integers are 4 bytes
NONCE_LENGTH = 4

class NonceInvalidError(Exception):
    pass

class MessageAuthenticationFailedError(Exception):
    pass

class Session:
    def __init__(self, socket, key: bytes, nonce_parity: int, nonce_lifespan:int = 30):
        self.socket = socket
        self.nonce_parity = nonce_parity
        self.nonce_lifespan = nonce_lifespan
        self.cryptobox = SymmetricCryptobox(key)
    
    def _get_nonce(self) -> bytes:
        timestamp = int(time.time())
        return (timestamp*2 + self.nonce_parity).to_bytes(length=4, byteorder='big')
    
    # returns true iff the nonce corresponds to a time within the nonce_lifespan
    def _is_nonce_valid(self, nonce: bytes):
        # the other party has the other nonce parity; adjust for that, then divide by 2 to get the timestamp
        nonce_int = int.from_bytes(nonce, byteorder='big')
        nonce_time = (nonce_int - ((self.nonce_parity + 1) % 2)) // 2
        current_time = int(time.time())

        nonce_age = current_time - nonce_time

        return nonce_age <= self.nonce_lifespan

    def _unpack_message(self, message):
        nonce = message[:4]
        ciphertext = message[4:-32]
        authentication_code = message[-32:]

        return nonce, ciphertext, authentication_code

    def _pack_message(self, nonce: bytes, ciphertext: bytes, authentication_code: bytes):
        message_length = NONCE_LENGTH + len(ciphertext) + HMAC_LENGTH
        return message_length.to_bytes(length=4, byteorder='big') + nonce + ciphertext + authentication_code

    def send(self, plaintext: bytes):
        nonce = self._get_nonce()
        ciphertext = self.cryptobox.encrypt(plaintext, nonce)
        authentication_code = self.cryptobox.generate_MAC(plaintext, nonce)
        message = self._pack_message(nonce, ciphertext, authentication_code)

        self.socket.send(message)
    
    def receive(self) -> bytes:
        incoming_length_bytes = self.socket.recv(4)
        incoming_length = int.from_bytes(incoming_length_bytes, byteorder='big')

        message = self.socket.recv(incoming_length)
        nonce, ciphertext, authentication_code = self._unpack_message(message)

        if not self._is_nonce_valid(nonce):
            raise NonceInvalidError()
        
        plaintext = self.cryptobox.decrypt(ciphertext, nonce)

        if not self.cryptobox.verify_MAC(plaintext, authentication_code, nonce):
            raise MessageAuthenticationFailedError()
        
        return plaintext

    def close(self):
        self.socket.close()

        
