import os


def create_directory(directory_path):
    if not os.path.isdir(directory_path):
        os.mkdir(directory_path)


def list_files(directory_path):
    files = '\n'.join([file_name for file_name in os.listdir(directory_path)])
    return files
