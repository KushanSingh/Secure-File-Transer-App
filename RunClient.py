import ClientSession
import Application
from Utilities import create_directory, list_files


_CLIENT_FILES_DIRECTORY = 'client_files/'


def client_controls(session):
    while True:
        print("\n1) List Files on Client")
        print("2) List Files on Server")
        print("3) Send File to Server")
        print("4) Get File from Server")
        print("5) Terminate session")
        choice = int(input('Select an option: '))

        # list files in _CLIENT_FILES_DIRECTORY
        if choice == 1:
            files = list_files(_CLIENT_FILES_DIRECTORY)
            print(files)
        # list files on server
        elif choice == 2:
            session.send(b'list files')
            data = session.receive().decode('utf-8')
            print(data)
        # send file to server
        elif choice == 3:
            file_name = input('Enter file name: ')
            PATH_TO_FILE = _CLIENT_FILES_DIRECTORY + file_name

            session.send(b'sending file')
            session.send(file_name.encode('utf-8'))
            Application.send_file(session, 'SERVER', PATH_TO_FILE)
        # get file from server
        elif choice == 4:
            file_name = input('Enter file name: ')
            PATH_TO_FILE = _CLIENT_FILES_DIRECTORY + file_name

            session.send(b'requesting file')
            session.send(file_name.encode('utf-8'))
            Application.get_file(session, 'SERVER', PATH_TO_FILE)
        # terminate session with server
        elif choice == 5:
            client.send(b'terminate')
            client.close()
            break
        else:
            print("Invalid option selected")


if __name__ == "__main__":
    # directory to store client files
    create_directory(_CLIENT_FILES_DIRECTORY)

    server_ip = input('Enter server ip: ')

    server_port = int(input('Enter server port: '))

    client = ClientSession.begin_session(server_ip, server_port)
    client_controls(client)
