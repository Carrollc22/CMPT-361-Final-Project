<<<<<<< Updated upstream
import socket
=======
import socket 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import os

# load_public_key
# save the key to a variable from a .pem file
# param: key_file. The file containing the key
# returns: public_key. The read key from the file.
def load_key(pem_file):
    # open and read pem file
    with open(pem_file, "rb") as key_file:
        # save key file to key
        key = RSA.import_key(key_file.read())
    return key

# encryption
# encrypt the message
# params: data, key
# return: encryped_data
def encryption(data, public_key):
    # init cipher with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    # encrypt data with cipher
    encrypted_data = cipher_rsa.encrypt(data)
    
    return encrypted_data
>>>>>>> Stashed changes

# decryption
# decrypt the incoming message
# Parameters: encrypted_data, key
# Returns: decrypted_data.decoode
def decryption(encrypted_data, private_key):
    # Init cipher with private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    # Decrypt data
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    
    # return decoded data
    return decrypted_data.decode('utf-8')

# start_client
# connects to server through known server ip and port
# params: server_ip, server_port. known ip and port addresses to start connection 
# return: none
def start_client(server_ip, server_port):
<<<<<<< Updated upstream
=======
    # get the server public key form server_public key file
    pem_file = "Client/server_public.pem"
    key = load_key(pem_file)

>>>>>>> Stashed changes
    # config socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((server_ip, server_port))

    # temporary server and client communication!!!

    welcome_message = client_socket.recv(1024).decode()

<<<<<<< Updated upstream
=======
    # Login Block
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    data = (username + "," + password).encode('utf-8')
    encrypted_creds = encryption(data, key)
    client_socket.send(encrypted_creds)
    response = client_socket.recv(1024).decode()

    if response == "success":
        print("Select the operation:")
    else:
        print("Invalid username or password.")
        print("Terminating.")

>>>>>>> Stashed changes
    while True:
        # user input
        message = input("You: ")
        client_socket.send(message.encode())

        # If the user types "exit", close the connection
        if message.lower() == "exit":
            print("Closing connection...")
            break

        # receive/print server response
        server_response = client_socket.recv(1024).decode()
        print("Server: ", server_response)

    # Close the client socket
    client_socket.close()

# Run the client
# server_ip = CHANGE TO YOUR DEVICES IP
server_port = 13000
start_client(server_ip, server_port)
