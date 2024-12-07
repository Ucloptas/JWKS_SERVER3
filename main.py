from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from cryptography.fernet import Fernet
from flask import request, jsonify
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher
from datetime import datetime, timedelta

hostName = "localhost"
serverPort = 8080
password = "test"
aes_key=base64.urlsafe_b64encode(password.ljust(32, '0')[:32].encode('utf-8'))
ph=PasswordHasher()
cipher=Fernet(aes_key)
conn = sqlite3.connect('totally_not_my_privateKeys.db')
try:
    #Create a cursor object, I learned its used to interact with the db (besides committing, thats through the connection)
    tableCursor = conn.cursor()

    #I learned a cursor executes sqlite commands to interact with table. making a table for good keys and one for expired keys.
    #tableCursor.execute("DROP TABLE IF EXISTS keys")
    #tableCursor.execute("DROP TABLE IF EXISTS users")
    tableCursor.execute("DROP TABLE IF EXISTS auth_logs")
    tableCursor.execute(''' 
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )   
    ''')
    tableCursor.execute(''' 
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
            )  
    ''')
    tableCursor.execute(''' 
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(username)
                        
            )    
    ''')
 

    # Step 4: Commit changes (the change of adding a table to the database)
    conn.commit()
    print("Created tables ok.")

except sqlite3.Error as e:
    #if there is an error then stop and report
    print(f"An error occurred in the database creation: {e}")
    conn.close()
    exit(1)

dbquery = 'INSERT INTO keys (key, exp) VALUES (?, ?)'




#generating the private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
#generating an expired key, which is not necissarily needed, can use bad time instead
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#converting key to a PEM encoded byte
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
# Encrypt the private key with AES using fernet
encrypted_pem = cipher.encrypt(pem)
#storing good encrypted key in database
qparams = (encrypted_pem, 1,)
tableCursor.execute(dbquery, qparams)
conn.commit()
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
#same process here encrypting in AES using fernet
encrypted_expired_pem = cipher.encrypt(expired_pem)
#storing expired encrypted key in database
qparams = (encrypted_expired_pem,0,)
tableCursor.execute(dbquery,qparams)
conn.commit()

#storing an object with the private key's information
numbers = private_key.private_numbers()

#converting from integer to base64 string
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    #converts to hex
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    #storing hex value as bytes
    value_bytes = bytes.fromhex(value_hex)
    #finally encoding translated value into base64 and removing unneeded =
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    #returning method not allowed for put, patch, delete and head
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

    def do_POST(self):
        #setup for operations
        timeformatstring = "%Y-%m-%d %H:%M:%S.%f"
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        newconn = sqlite3.connect('totally_not_my_privateKeys.db')
        newconn.execute("PRAGMA foreign_keys = ON")
        newCursor = newconn.cursor()

        #used if auth command was called
        newCursor.execute("SELECT key FROM keys WHERE exp = 1 LIMIT 1")

        #getting key from database, decrypting
        keyFromDatabase = newCursor.fetchone()[0]
        keyFromDatabase =  cipher.decrypt(keyFromDatabase)

        #getting most recent timestamp
        newCursor.execute("SELECT request_timestamp FROM auth_logs ORDER BY request_timestamp ASC LIMIT 1")
        gettime = newCursor.fetchone()
        if(gettime is not None):
            last_request = datetime.strptime(gettime[0],timeformatstring)
        else:
            last_request="error"

        if parsed_path.path == "/auth":
            if(last_request!="error"): 
                if((datetime.now()-timedelta(seconds=.1))>last_request):
                    self.send_response(429)
                    self.end_headers()
                    return
            #storing auth requests, for some reason it is not actually going into the db according to gradebot
            last_request = datetime.now()
            last_request = last_request.strftime(timeformatstring)
            post_data = self.rfile.read(int(self.headers['Content-Length']))
            json_data = json.loads(post_data)
            username_data= json_data.get("username")
            insert_perams=(self.client_address[0], last_request, username_data,)
            insert_command="INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)"
            #proof that the data is good
            print(f"Client IP: {self.client_address[0]}")
            print(f"Last Request: {last_request}")
            print(f"Username Data: {username_data}")
            newCursor.execute(insert_command, insert_perams)
            newconn.commit()

            #setting up jwt
            headers = { #defining header for jwt
                "kid": "goodKID"
            }
            token_payload = {#defining payload for jwt
                "user": "username",
                #expiry one hour from issuance
                "exp": datetime.utcnow() + timedelta(hours=1)
            }
            if 'expired' in params:
                exp_query = ("SELECT key FROM keys WHERE exp = ? LIMIT 1")
                newCursor.execute(exp_query, (0,))
                keyFromDatabase = newCursor.fetchone()[0]
                keyFromDatabase =  cipher.decrypt(keyFromDatabase)

                headers["kid"] = "expiredKID" #soft labelling as expired, no real effect in code
                #setting expiry to one hour ago
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            #creating jwt
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            newCursor.close()
            #giving the encoded jwt in byte form coded in utf8
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return
        elif parsed_path.path == "/register":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            post_data = self.rfile.read(int(self.headers['Content-Length']))
            data = json.loads(post_data)
            if not data or 'username' not in data or 'email' not in data: #make sure that we have data and it is correct
                return jsonify({"error": "Invalid input. 'username' and 'email' are required fields."}), 400
            username = data['username']
            email = data['email']
            uuid_password = str(uuid.uuid4()) #generating secure password with uuid4
            password_json = {"password": uuid_password}
            self.wfile.write(bytes(json.dumps(password_json), "utf-8"))
            hashed_password = ph.hash(uuid_password)
            insert_perams=(username,hashed_password,email,datetime.now())
            insert_command="INSERT INTO users (username, password_hash,email,last_login) VALUES (?, ?, ?, ?)"
            newCursor.execute(insert_command, insert_perams)
            newconn.commit()
            return
        #if it was not auth that was called, return not allowed
        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        #if allowed path is the one called
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                #formatting / making object for provided key
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            #returns a json formatted representation of the public key
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return
        #if other path called thats not allowed, smack it down
        self.send_response(405)
        self.end_headers()
        return

#actually runs the server
if __name__ == "__main__":
    #names the server and defines port 8080, and uses functions defined in myserver class
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        #runs the loop foreve until...
        webServer.serve_forever()
    #the keyboard interrupt is used, and breakes out of the loop via except
    except KeyboardInterrupt:
        pass

    #closes database connection
    if conn:
        conn.close()
    #closes web server
    webServer.server_close()