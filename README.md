🔐 Keylogger with RSA Encryption
A secure keylogger implementation that captures keystrokes and encrypts the captured data using RSA encryption. This project demonstrates how access control mechanisms and encryption can safeguard sensitive information.

✨ Features
🖥️ Keylogging:
Real-time capture of user keystrokes.

🔒 RSA Encryption:
Encrypts the captured text using RSA public-key cryptography, ensuring only authorized individuals with the private key can decrypt the data.

🛡️ Access Control:
Implements security measures to protect sensitive data from unauthorized access.

📚 Use Cases
🎓 Demonstrating the integration of cryptographic algorithms in applications.
🛠️ Understanding access control and encryption mechanisms.
🧑‍🏫 Educational purposes for exploring how RSA encryption works with real-time data capture.

 Prerequisites
Before running this project, ensure you have:

🐍 Python 3.x installed on your system.
📦 Required Python libraries:
cryptography
pynput

🛠️ How It Works
🎹 Keystroke Capture:
The pynput library captures user keystrokes in the background.

🔐 Data Encryption:
Captured text is encrypted using the RSA public key from public_key.pem.

💾 Data Storage:
The encrypted keystrokes are stored securely in a file for later retrieval.

🔓 Decryption:
Using the private key (private_key.pem), the encrypted data can be decrypted and viewed.
