# Secure-File-Transfer-App

# Required Packages

- Cryptodome (for certificate generation)
- OpenSSL (for certificate verification)

# Running the Project

When running the server, it will automatically generate certificates and keys if they are not present.

1. Run the server with `python3 RunServer.py`
    1. Note the IP and port displayed
2. Run the client iwth `python3 RunClient.py` (in a separate terminal or on a different machine)
    1. Enter the server IP and port noted from earlier
3. Follow menu prompts to list files on the client and server, or pass files between the client and server

# File Structure

Certificates are stored in /certs

Private keys are stored in /private

Public keys are stored in /public

Client files are stored in /client_files

Server files are stored in /server_files
