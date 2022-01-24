import os


def send_file(session, destination, PATH_TO_FILE):
    file_name = PATH_TO_FILE.split('/')[-1]
    print(f'Sending {file_name} to {destination}')

    with open(PATH_TO_FILE, 'rb') as f:
        while True:
            data = f.read(1024)
            session.send(data)
            if not data:
                break


def get_file(session, destination, PATH_TO_FILE):
    with open(PATH_TO_FILE, 'wb') as f:
        while True:
            data = session.receive()
            if not data:
                break
            f.write(data)

    file_name = PATH_TO_FILE.split('/')[-1]
    print(f'Received {file_name} from {destination}')


def list_files(session, DIRECTORY):
    files = '\n'.join([file_name for file_name in os.listdir(DIRECTORY)])
    session.send(files.encode('utf-8'))
