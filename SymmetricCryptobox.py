from hashlib import sha256
import math

def _xor_bytes(first: bytes, second: bytes):
    return bytes(map(lambda f, s: f ^ s, first, second))

def _subtract_bytes(first: bytes, second: bytes):
    return bytes(map(lambda f, s: (f - s) % 256, first, second))

def _add_bytes(first: bytes, second: bytes):
    return bytes(map(lambda f, s: (f + s) % 256, first, second))

# The SymmetricCryptobox class handles all low-level cryptographic operations for symmetric key cryptography 
class SymmetricCryptobox():
    def __init__(self, secret_key: bytes):
        self._secret_key = secret_key
        self.block_size = 32

    def _hash(self, text: bytes):
        return sha256(text).digest()

    def _generate_confidentiality_key(self, nonce: bytes) -> bytes:
        return self._hash(_add_bytes(self._secret_key, nonce))

    def _generate_integrity_key(self, nonce: bytes) -> bytes:
        return self._hash(_subtract_bytes(self._secret_key, nonce))

    # HMAC is a standard keyed hash mechanism
    def _HMAC(self, text: bytes, hmac_key: bytes) -> bytes:
        
        # Normalize the hmac key length to be the same as the block size
        if len(hmac_key) > self.block_size:
            hmac_key = self._hash(hmac_key)
        
        if len(hmac_key) < self.block_size:
            hmac_key += b'\x00' * (self.block_size - len(hmac_key))

        # Calculate outer and inner pads
        outer_pad = _xor_bytes(hmac_key, b'\x5c' * self.block_size)
        inner_pad = _xor_bytes(hmac_key, b'\x36' * self.block_size)

        # By hashing twice with padding, we defend against length extension attacks
        return self._hash(outer_pad + self._hash(inner_pad + text))

    def get_random_bytes(self, num_bytes: int, seed: bytes):
        if num_bytes <= 0:
            return b''

        # calculate the number of requested blocks
        num_blocks = math.ceil(num_bytes / self.block_size)

        # begin by hashing the seed with the secret key
        last_result = self._HMAC(seed, self._secret_key)
        result_bytes = [last_result]

        # generate the required number of blocks by iteratively hashing the last block
        for iteration in range(1, num_blocks):
            last_result = self._HMAC(last_result, self._secret_key)
            result_bytes.append(last_result)

        # join results and truncate to the number of requested bytes
        return b''.join(result_bytes)[:num_bytes]

    def generate_MAC(self, message: bytes, nonce: bytes):
        integrity_key = self._generate_integrity_key(nonce)
        return self._HMAC(message, integrity_key)

    def verify_MAC(self, message: bytes, mac: bytes, nonce: bytes):
        candidate_mac = self.generate_MAC(message, nonce)
        return candidate_mac == mac
    
    def _crypt(self, message: bytes, nonce: bytes):
        confidentiality_key = self._generate_confidentiality_key(nonce)
        keystream = self.get_random_bytes(len(message), confidentiality_key)
        return _xor_bytes(message, keystream)
    
    # encryption and decryption are the same in our cryptographic scheme
    def encrypt(self, message: bytes, nonce: bytes):
        return self._crypt(message, nonce)
    def decrypt(self, message: bytes, nonce: bytes):
        return self._crypt(message, nonce)

# Validation Testing
if __name__ == "__main__":
    box = SymmetricCryptobox(b'123456789')
    myMessage = b'Hello, World!'
    changedMessage = b'Goodbye, World!'
    myNonce = b'abcdef'
    mySecondNonce = b'fdksnajgfd'
    
    ciphertext = box.encrypt(myMessage, myNonce)
    print(ciphertext)
    plaintext = box.decrypt(ciphertext, myNonce)
    print(plaintext)

    ciphertext2 = box.encrypt(myMessage, mySecondNonce)
    print(ciphertext2)
    plaintext2 = box.decrypt(ciphertext2, mySecondNonce)
    print(plaintext2)

    mac = box.generate_MAC(myMessage, myNonce)
    print(mac)
    if box.verify_MAC(myMessage, mac, myNonce):
        print('Success!')
    else:
        print('Fail!')
    
    if box.verify_MAC(changedMessage, mac, myNonce):
        print('Fail!')
    else:
        print('Success!')
    
