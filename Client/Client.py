import socket 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import os

# load_key
# save the key to a variable from a .pem file
# param: key_file. The file containing the key
# returns: public_key. The read key from the file.
def load_key(pem_file):
    # open and read pem file
    with open(pem_file, "rb") as key_file:
        # save key file to key
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
# decrypt the incoming message with rsa
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
# decrypt the incoming message with aes
# Parameters: encrypted_data, key
# Returns: unpadded_data.decoode
def decryptionAES(encrypted_data, sym_key):
    # init cipher 
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # decrypt
    decrypted_data = cipher.decrypt(encrypted_data)
    
    #unpad
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode('utf-8')

# start_client
# connects to server through known server ip and port
# params: server_ip, server_port. known ip and port addresses to start connection 
# return: none
def start_client(server_ip, server_port):
    # get the server public key form server_public key file
    pem_file = "Client/server_public.pem"
    key = load_key(pem_file)

    # config socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((server_ip, server_port))

    client_socket.recv(1024).decode()

    # login block
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    data = (username + "," + password).encode('utf-8')
    encrypted_creds = encryptionRSA(data, key)
    client_socket.send(encrypted_creds)
    
    # check if valid login
    response = client_socket.recv(1024).decode()
    if response == "Invalid username or password":
        print("Invalid username or password.")
        print("Terminating.")
        client_socket.close()
        return
    
    # receive encrypted key
    encrypted_sym_key = client_socket.recv(1024)

    # load client's private key and decrypt sym_key
    client_private_file = f"Client/{username}_private.pem"
    client_private_key = load_key(client_private_file)
    cipher_rsa = PKCS1_OAEP.new(client_private_key)
    sym_key = cipher_rsa.decrypt(encrypted_sym_key)

    # send ok with sym_key
    message = encryptionAES("OK".encode('utf-8'), sym_key)
    client_socket.send(message)

    while True:
 
            # receive encrypted menu
            encrypted_menu = client_socket.recv(1024)
             
            # decrypt and display menu
            menu = decryptionAES(encrypted_menu, sym_key)
            print(menu, end="")
             
            # get user choice
            choice = input()
             
            # encrypt and send choice
            encrypted_choice = encryptionAES(choice.encode("utf-8"), sym_key)
            client_socket.send(encrypted_choice)
             
             
            if choice == '1':
                print("Sending email subprotocol")
                 
            elif choice == '2':
                print("Viewing inbox subprotocol")
                 
            elif choice == '3':
 
                # IMPLEMENT VIEW EMAIL SUBPROTOCOL
                 
                print("Viewing email subprotocol")
                 
            elif choice == '4':
                print("The connection is terminated with the server.")
                break
            else:
                print("Invalid choice. Please try again.")
                 
    # Close the client socket
    client_socket.close()

# run client
if __name__ == "__main__":
    server_ip = "127.0.0.1"
    server_port = 13000
    start_client(server_ip, server_port)
