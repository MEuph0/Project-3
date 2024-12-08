''' 
CSCE 3550 Project 3
Mason Willy

'''

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import sqlite3
import base64
import json
import jwt
import datetime
import uuid
import os

hostName = "localhost"
serverPort = 8080

''' Create a database file and populate with private keys'''
conn = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')

# Create users table
cursor.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)''')

# Create auth_logs table
cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
)''')

os.environ["NOT_MY_KEY"] = str(Fernet.generate_key().decode("utf-8"))

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

pem = Fernet(bytes(os.environ.get("NOT_MY_KEY"),"utf-8")).encrypt(pem)
expired_pem = Fernet(bytes(os.environ.get("NOT_MY_KEY"), "utf-8")).encrypt(expired_pem)

cursor.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (pem, False))
cursor.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (expired_pem, True))
conn.commit()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    ''' Updated POST function to have /register endpoint '''
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":            
            request_headers = self.headers
            content_length = request_headers.get_all('Content-Length')
            length = int(content_length[0]) if content_length else 0

            content = self.rfile.read(length)
            token = json.loads(content)
            username = token["username"]
            exp = datetime.datetime.now() + datetime.timedelta(hours=1)

            cursor.execute('SELECT id from users WHERE username=(?)', (username,))
            list_id = cursor.fetchone()
            for nums in list_id:
                user_id = nums
            request_ip = self.client_address[0]
            cursor.execute("INSERT INTO auth_logs (user_id, request_ip) VALUES (?,?)", (user_id, request_ip))
            conn.commit()
            
            payload = {"username": username,
                       "exp": exp}

            if 'expired' in params:
                cursor.execute('SELECT * FROM keys WHERE exp=True')
                row = cursor.fetchone()
                pem = Fernet(bytes(os.environ.get("NOT_MY_KEY"), "utf-8")).decrypt(row[1]).decode()
                exp = datetime.datetime.now() - datetime.timedelta(hours=1)
            else:
                cursor.execute('SELECT * FROM keys')
                row = cursor.fetchone()
                pem = Fernet(bytes(os.environ.get("NOT_MY_KEY"), "utf-8")).decrypt(row[1]).decode()

            headers = {
                "kid": f"{row[0]}"
            }
            
            encoded_jwt = jwt.encode(payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        
        if parsed_path.path == "/register":
            request_headers = self.headers
            content_length = request_headers.get_all('Content-Length')
            length = int(content_length[0]) if content_length else 0

            
            content = self.rfile.read(length)
            token = json.loads(content)
            username = token["username"]
            email = token["email"]
            password = str(uuid.uuid4())
            password_json = {"password": password}
            self.send_response(201)
            self.end_headers()
            self.wfile.write(bytes(json.dumps(password_json), "utf-8"))

            ph = PasswordHasher()
            password_hash = ph.hash(password)
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?,?,?)", (username, password_hash, email))
            conn.commit()
            return


        self.send_response(405)
        self.end_headers()
        return

    ''' Updated GET function to use database '''
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            time = datetime.datetime.now()
            cursor.execute('SELECT * FROM keys WHERE exp=False')
            rows = cursor.fetchall()
            keys = {"keys": []}
            for row in rows:
                decrypted_key = Fernet(bytes(os.environ.get("NOT_MY_KEY"), "utf-8")).decrypt(row[1])
                key = serialization.load_pem_private_key(decrypted_key, password=None)
                numbers = key.private_numbers()
                jwt_key = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": f"{row[0]}",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                keys["keys"].append(jwt_key)
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    
    conn.close()
    webServer.server_close()
