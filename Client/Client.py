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

# start_client
# connects to server through known server ip and port
# params: server_ip, server_port. known ip and port addresses to start connection 
# return: none
def start_client(server_ip, server_port):

    # get username and password from user
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # get the server public key form server_public key file
    pem_file = "Client/server_public.pem"
    key = load_key(pem_file)

    # load client's private key
    client_private_file = f"Client/{username}_private.pem"
    client_private_key = load_key(client_private_file)

    # config socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((server_ip, server_port))

    # temporary server and client communication!!!

    welcome_message = client_socket.recv(1024).decode()

    # Login Block
    
    data = (username + "," + password).encode('utf-8')
    encrypted_creds = encryption(data, key)
    client_socket.send(encrypted_creds)
    response = client_socket.recv(1024).decode()

    print(f"Received response: {response}")

    if response == "success":
        print("Authentication successful, waiting for symmetric key...")
        # get symmetric key from server
        encrypted_sym_key = client_socket.recv(1024)
         # Initialize the cipher for decryption
        cipher_rsa = PKCS1_OAEP.new(client_private_key)
    
        # Decrypt the symmetric key
        sym_key = cipher_rsa.decrypt(encrypted_sym_key)
        
        # send "OK" message encrypted with symmetric key
        ok_message = "OK"
        encrypted_ok = encrypt_with_symmetric_key(ok_message, sym_key)
        client_socket.send(encrypted_ok)


        # menu loop
        while True:

            # receive encrypted menu
            encrypted_menu = client_socket.recv(1024)
            
            # decrypt and display menu
            menu = decrypt_with_symmetric_key(encrypted_menu, sym_key)
            print(menu, end="")
            
            # get user choice
            choice = input()
            
            # encrypt and send choice
            encrypted_choice = encrypt_with_symmetric_key(choice, sym_key)
            client_socket.send(encrypted_choice)
            
            
            if choice == '1':

                # IMPLEMENT SEND EMAIL SUBPROTOCOL

                print("Sending email subprotocol")
                
            elif choice == '2':

                # IMPLEMENT VIEW INBOX SUBPROTOCOL

                print("Viewing inbox subprotocol")
                
            elif choice == '3':

                # IMPLEMENT VIEW EMAIL SUBPROTOCOL
                
                print("Viewing email subprotocol")
                
            elif choice == '4':
                print("The connection is terminated with the server.")
                break
            else:
                print("Invalid choice. Please try again.")

    else:
        print("Invalid username or password.")
        print("Terminating.")

    # Close the client socket
    client_socket.close()


# run client
if __name__ == "__main__":
    server_ip = "127.0.0.1"
    server_port = 13000
    start_client(server_ip, server_port)

