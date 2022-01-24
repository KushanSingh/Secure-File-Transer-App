import ServerSession
import Application
from Utilities import create_directory, list_files
from KeyCertificateTemplate import generate_keys_and_certs

_SERVER_FILES_DIRECTORY = 'server_files/'


def server_controls(session):
    while True:
        data = server.receive()
        # retreive the file name and store it in _SERVER_FILES_DIRECTORY
        if data == b'sending file':
            file_name = session.receive().decode('utf-8')
            PATH_TO_FILE = _SERVER_FILES_DIRECTORY + file_name
            Application.get_file(session, 'CLIENT', PATH_TO_FILE)
        # send the requested file to the client
        elif data == b'requesting file':
            file_name = session.receive().decode('utf-8')
            PATH_TO_FILE = _SERVER_FILES_DIRECTORY + file_name
            print(PATH_TO_FILE)
            Application.send_file(session, 'CLIENT', PATH_TO_FILE)
        # send the list of files in _SERVER_FILES_DIRECTORY to the client
        elif data == b'list files':
            files = list_files(_SERVER_FILES_DIRECTORY)
            session.send(files.encode('utf-8'))
        # terminate session with client
        elif data == b'terminate':
            server.close()
            break
        else:
            server.send(b'Invalid request')


if __name__ == "__main__":
    # directory to store server files
    create_directory(_SERVER_FILES_DIRECTORY)

    # generate keys and certificates for both root and server
    generate_keys_and_certs()

    for server in ServerSession.init_listener(9999):
        # maintain a persistent session
        server_controls(server)
