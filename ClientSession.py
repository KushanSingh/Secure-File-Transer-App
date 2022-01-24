import secrets
from AsymmetricCryptobox import AsymmetricCryptobox
from Session import Session

# used for session key generation
import secrets

import time
import socket

from hashlib import sha256

PATH_TO_SERVER_CERTIFICATE = './certs/server.crt'
PATH_TO_SERVER_PUBLIC_KEY = './public/server.pem'
PATH_TO_ROOT_CERTIFICATE = './certs/root.crt'

MESSAGE_LIFESPAN = 30

class ServerResponseMismatchError(Exception):
    pass

def begin_session(server_ip, server_port):

    cryptobox = AsymmetricCryptobox(PATH_TO_SERVER_CERTIFICATE, PATH_TO_SERVER_PUBLIC_KEY, None, PATH_TO_ROOT_CERTIFICATE)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    # generate R1 and timestamp
    client_random_number = secrets.token_bytes(32)
    timestamp = int(time.time()).to_bytes(4, byteorder='big')

    # send to server
    handshake_message = client_random_number + timestamp
    handshake_encrypted = cryptobox.encrypt(handshake_message)
    client_socket.send(handshake_encrypted)

    # receive server response
    server_random_number = client_socket.recv(32)

    # generate session key K = hash(R1, R2)
    session_key = sha256(client_random_number + server_random_number).digest()
    session = Session(client_socket, session_key, nonce_parity=0)

    # receive the rest of the server's response
    handshake_response = session.receive()

    # check that the handshake matches
    if handshake_response != handshake_message:
        print('SESSION INITIALIZATION FAILED: RESPONSE MISMATCH')
        raise ServerResponseMismatchError()

    return session

# validation testing
if __name__ == '__main__':
    session = begin_session('127.0.1.1', 9999)
    message = b'Hello, World!'
    print(f'Sending to server: {message}')
    session.send(message)
    session.close()


