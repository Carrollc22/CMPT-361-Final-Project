import socket 
import threading 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import os


MENU = "Select the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\nchoice: "
 
 
# load_key
# save the key to a variable from a .pem file
# param: key_file. The file containing the key
# returns: public_key. The read key from the file.
def load_key(pem_file):
    with open(pem_file, "rb") as key_file:
        key = RSA.import_key(key_file.read())
    return key

# encryptionRSA
# encrypt the message with RSA for assymetric keys
# params: data, public_key
# return: encryped_data
def encryptionRSA(data, public_key):
    # init cipher with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    # encrypt data with cipher
    encrypted_data = cipher_rsa.encrypt(data)
    
    return encrypted_data

# encryptionAES
# encrypt the message with AES for symmetric keys
# params: data, sym_key
# returns: encrypted_data
def encryptionAES(data, sym_key):
    padded_data = pad(data, AES.block_size)
    
    cipher = AES.new(sym_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

# decryptionRSA
# decrypt the incoming message
# Parameters: encrypted_data, key
# Returns: decrypted_data.decoode
def decryptionRSA(encrypted_data, private_key):
    # Init cipher with private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    # Decrypt data
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    
    # return decoded data
    return decrypted_data.decode('utf-8')

# decryptionAES
# decrypt the username and password
# Parameters: encrypted_data, key
# Returns: unpadded_data.decoode
def decryptionAES(encrypted_data, sym_key):
    # create an AES cipher object with the key in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    decrypted_data = cipher.decrypt(encrypted_data)

    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode('utf-8')

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
    pem_file = "Server/server_private.pem"
    key = load_key(pem_file)

    client_socket.send(b"Hello from the server!")

    # Receive encrypted username/password
    encrypted_data = client_socket.recv(1024)

    # Decrypt encrypted username/password
    decrypted_data = decryptionRSA(encrypted_data, key)

    # Split 
    username, password = decrypted_data.split(',')

    # validate with json file and get public key
    if validation(username, password):
        # generate sym key for future aes encrytion
        sym_key = get_random_bytes(32)
        
        # get user public key for rsa
        if username == "client1":
            pem_file = "Server/Client1/client1_public.pem"
        elif username == "client2":
            pem_file = "Server/Client2/client2_public.pem"
        elif username == "client3":
            pem_file = "Server/Client3/client3_public.pem"
        elif username == "client4":
            pem_file = "Server/Client4/client4_public.pem"
        elif username == "client5":
            pem_file = "Server/Client5/client5_public.pem"
        key = load_key(pem_file)

        # success 
        client_socket.send("success".encode())
        client_socket.send(encryptionRSA(sym_key, key))
        print("Connection Accepted and Symmetric Key Generated for client:", username)
    else:
        # fail
        client_socket.send("Invalid username or password".encode())
        print("The received client information:", username, "is invalid (Connection Terminated).")
        return

    # ok message
    encrypted_data = client_socket.recv(1024)
    message = decryptionAES(encrypted_data, sym_key)

    if message != "OK":
        return
    
            # menu loop
    while True:
 
        # encrypt menu and send to client
        encrypted_menu = encryptionAES(MENU.encode("utf-8"), sym_key)
        client_socket.send(encrypted_menu)
 
        # receive encrypted choice from client
        encrypted_choice = client_socket.recv(1024)
        choice = decryptionAES(encrypted_choice, sym_key)
 
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







                      