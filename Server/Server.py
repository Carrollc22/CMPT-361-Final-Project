import socket 
import threading 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import json
import os


MENU = "Select the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\nchoice: "

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



# generate_symmetric_key
# generate a symmetric key for AES encryption
# parameters: none
# returns: sym_key
def generate_symmetric_key():
    return os.urandom(32)

# encrypt_with_client_key
# encrypt data with client's public key
# parameters: data, client_username
# returns: encrypted_data
def encrypt_with_client_key(data, client_username):
    # load client's public key
    client_key_path = f"Server/{client_username}_public.pem"
    client_public_key = load_key(client_key_path)
    
    # encrypt with client's public key
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    
    return encrypted_data

# encrypt_with_symmetric_key
# encrypt data with symmetric key
# parameters: data, sym_key
# returns: encrypted_data
def encrypt_with_symmetric_key(data, sym_key):
    
    # create AES cipher
    cipher = AES.new(sym_key, AES.MODE_ECB)
    
    # prepare and encrypt data
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data

# decrypt_with_symmetric_key
# decrypt data with symmetric key
# parameters: encrypted_data, sym_key
# returns: decrypted_data
def decrypt_with_symmetric_key(encrypted_data, sym_key):
    # create AES cipher
    cipher = AES.new(sym_key, AES.MODE_ECB)
    
    # decrypt and unpad data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    return decrypted_data.decode('utf-8')

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
    # AES encryption key
    pem_file = "Server/server_private.pem"
    key = load_key(pem_file)

    # temporary client handling!!!!!!

    client_socket.send(b"Hello from the server!")

    # Receive encrypted data
    encrypted_data = client_socket.recv(1024)

    # Decrypt encrypted data
    decrypted_data = decryption(encrypted_data, key)

    # Split the data
    username, password = decrypted_data.split(',')

    if validation(username, password):

        # generate symmetric key
        sym_key = generate_symmetric_key()

        # encrypt symmetric key with client's public key
        encrypted_sym_key = encrypt_with_client_key(sym_key, username)

        # send success message
        client_socket.send("success".encode())

        # send the encrypted symmetric key
        client_socket.send(encrypted_sym_key)

        print("Connection Accepted and Symmetric Key Generated for client:", username)

        # receive "OK" message from client
        encrypted_ok = client_socket.recv(1024)
        ok_message = decrypt_with_symmetric_key(encrypted_ok, sym_key)
        print(f"Received acknowledgment: {ok_message}")

        # menu loop
        while True:

            # encrypt menu and send to client
            encrypted_menu = encrypt_with_symmetric_key(MENU, sym_key)
            client_socket.send(encrypted_menu)

            # receive encrypted choice from client
            encrypted_choice = client_socket.recv(1024)
            choice = decrypt_with_symmetric_key(encrypted_choice, sym_key)

            if choice == '1':
                    
                    # IMPLEMENT SEND EMAIL SUBPROTOCOL

                    print(f"Client {username} selected: Send email")
                    
                    
            elif choice == '2':

                # IMPLEMENT VIEW INBOX SUBPROTOCOL

                print(f"Client {username} selected: View inbox")
                
                
            elif choice == '3':

                # IMPLEMENT VIEW EMAIL SUBPROTOCOL

                print(f"Client {username} selected: View email content")
                
                
            elif choice == '4':

                # terminate connection

                print(f"Terminating connection with {username}.")
                break
            else:
                print(f"Invalid choice received from {username}: {choice}")


    else:
        client_socket.send("fail".encode())
        print("The received client information:", username, "is invalid (Connection Terminated).")

    
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

    # CHANGED TO LOCOALHOST FOR TESTING
    # SHOULD BE server_ip
    server_socket.bind(("127.0.0.1", 13000))  
    server_socket.listen(5)

    # Accept incoming client connections
    while True:
        # Accept incoming client connections
        client_socket, client_address = server_socket.accept()
        
        # Handle each client connection in a new thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()







                      