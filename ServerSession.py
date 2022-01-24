import secrets
from AsymmetricCryptobox import AsymmetricCryptobox
from Session import Session

# used for session key generation
import secrets

import time
import socket

from hashlib import sha256

PATH_TO_LOCAL_PRIVATE_KEY = './private/server.pem'

MESSAGE_LIFESPAN = 30

class ClientMessageExpiredError(Exception):
    pass

def init_listener(port):
    welcome_mat = socket.socket()
    welcome_mat.bind((socket.gethostname(), port))
    welcome_mat.listen(1)

    print(f'Waiting for connections on {socket.gethostbyname(socket.gethostname())}:{port}...')

    # listen for new connections, yielding them to the application layer
    while True:
        session_socket, _ = welcome_mat.accept()
        yield begin_session(session_socket)


def begin_session(session_socket):

    cryptobox = AsymmetricCryptobox(None, None, PATH_TO_LOCAL_PRIVATE_KEY, None)

    # receive client handshake message
    client_message = session_socket.recv(128)
    client_message_clear = cryptobox.decrypt(client_message)

    # validate timestamp
    timestamp_bytes = client_message_clear[32:36]
    timestamp = int.from_bytes(timestamp_bytes, byteorder='big')

    if int(time.time()) - timestamp > MESSAGE_LIFESPAN:
        print(f'SESSION INITIALIZATION FAILED: CLIENT MESSAGE EXPIRED')
        raise ClientMessageExpiredError()
    
    # parse out R1
    client_random_number = client_message_clear[:32]

    # generate R2
    server_random_number = secrets.token_bytes(32)

    # send R2 to client for key generation
    session_socket.send(server_random_number)

    # generate session key K = hash(R1, R2), create session
    session_key = sha256(client_random_number + server_random_number).digest()
    session = Session(session_socket, session_key, nonce_parity=1)

    # send (R1, T) back to client using the session key 
    session.send(client_message_clear)

    return session

# validation testing
if __name__ == "__main__":
    for session in init_listener(9999):
        print(f'Message from client: {session.receive()}')
        session.close()




