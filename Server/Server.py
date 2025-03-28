import socket 
import threading 
<<<<<<< Updated upstream
=======
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import json
import os

# load_public_key
# save the key to a variable from a .pem file
# param: key_file. The file containing the key
# returns: public_key. The read key from the file.
def load_key(pem_file):
    with open(pem_file, "rb") as key_file:
        key = RSA.import_key(key_file.read())
    return key

# encryption
# encrypt the message
# params: username, password, key
# return: encryped_data
def encryption(username, password, public_key):
    data = (username + "," + password).encode('utf-8')
    padded_data = pad(data, AES.block_size)
    
    cipher = AES.new(public_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

# decryption
# decrypt the incoming message
# Parameters: encrypted_data, key
# Returns: unpadded_data.decoode
def decryption(encrypted_message, private_key):
    # Initialize the RSA cipher with the private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    # Decrypt the encrypted message
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    
    # Return the decrypted message (it will be in bytes, so we decode it to a string)
    return decrypted_message.decode('utf-8')

# validation
# validate whether or not the username and password are acceptable
# Parameters: username, password
# Returns: True
def validation(username, password):
    with open('Server/user_pass.json', 'r') as file:
            valid_clients = json.load(file)

    if username in valid_clients and valid_clients[username] == password:
        return True
    return False
>>>>>>> Stashed changes

# Get_server_ip 
# find the ip of the machine running the server program. Allows for a dynamic ip address when running the server. 
# Paramaters: none
# Returns: server_ip. The ip address of the machine running the server program
def get_server_ip():
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # connect to public server
    s.connect(("8.8.8.8", 80))  

    # find local ip 
    server_ip = s.getsockname()[0] 

    # close socket and return local ip
    s.close()
    return server_ip

# handle_client
# process of handling client connection. calls subprotocols to handle client requests.
# parameters: client_socket. The socket connection between server and client.
# returns: none
def handle_client(client_socket, client_address):
<<<<<<< Updated upstream
=======
    # AES encryption key
    pem_file = "Server/server_private.pem"
    key = load_key(pem_file)
>>>>>>> Stashed changes

    # temporary client handling!!!!!!

    client_socket.send(b"Hello from the server!")

<<<<<<< Updated upstream
    client_message = client_socket.recv(1024).decode("utf-8")
    print("Received from client: ", client_message)
=======
    # Receive encrypted data
    encrypted_data = client_socket.recv(1024)

    # Decrypt encrypted data
    decrypted_data = decryption(encrypted_data, key)

    # Split the data
    username, password = decrypted_data.split(',')

    if validation(username, password):
        client_socket.send("success".encode())
        print("Connection Accepted and Symmetric Key Generated for client:", username)
    else:
        client_socket.send("fail".encode())
        print("The received client information:", username, "is invalid (Connection Terminated).")
>>>>>>> Stashed changes

    
    client_socket.close()

# start_server
# configure server to listen for connection on port 13000 and machine ip 
# param: none
# returns: none
def start_server():
    # Get server machine ip
    server_ip = get_server_ip()

    print("The server is ready to accept connections")

    # Create a socket and bind to the machine ip and port 13000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, 13000))  
    server_socket.listen(5)

    # Accept incoming client connections
    while True:
        # Accept incoming client connections
        client_socket, client_address = server_socket.accept()
        
        # Handle each client connection in a new thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

start_server()







                      