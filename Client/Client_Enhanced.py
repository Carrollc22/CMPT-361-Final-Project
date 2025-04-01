import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import datetime
import json
import sys
import os






# format_email
# get user input and format email to send
# param: username
# returns: formatted_email
def format_email(username):
    # user input
    destinations = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")
    file_load = input("Would you like to load contents from a file?(Y/N): ")
    while((file_load != "Y") and (file_load != "N")):
        file_load = input("Invalid Choice. Would you like to load contents from a file?(Y/N): ")
   
    # Get message from existing file
    if file_load == "Y":
        send_file = input("Enter filename: ")
        # ensure file exists
        if not(os.path.exists(f"Client/{send_file}")):
            send_file = input("Not an existing file. Enter filename: ")
        with open(f"Client/{send_file}", 'r') as file:
                send_content = file.read()
   
    elif file_load == "N":
        send_content = input("Enter message contents: ")


    content_length = len(send_content)


    # format
    message = f"From: {username}\n" \
              f"To: {destinations}\n" \
              f"Title: {title}\n" \
              f"Content Length: {content_length}\n" \
              f"Content: {send_content}"
    return message

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
# encrypt the message with RSA for assymetric keys generate nonce to send to server
# params: data, public_key
# return: encryped_data + nonce
def encryptionRSA(data, public_key):
    # generate nonce to send
    nonce = get_random_bytes(16)

    print(f"Nonce generated, sending with message: {nonce}")
    # init cipher with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
   
    # encrypt data with cipher
    encrypted_data = cipher_rsa.encrypt(data)
   
    return nonce + encrypted_data


# encryptionAES
# encrypt the message with AES for symmetric keys generate nonce to send to server
# params: data, sym_key
# returns: encrypted_data + nonce
def encryptionAES(data, sym_key):
    # Generate nonce to send
    nonce = get_random_bytes(16)
    print(f"Nonce generated, sending with message: {nonce}")
    padded_data = pad(data, AES.block_size)
   
    cipher = AES.new(sym_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    return nonce + encrypted_data

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
    unpadded_data = unpad(decrypted_data, AES.block_size)
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

# send_email_subprotocol
# send the email to the server
# params: client_socket, sym_key, username
# return: none
def send_email_subprotocol(client_socket, sym_key, username):
        # receive confirmation server is ready
    encrypted_confirmation = client_socket.recv(1024)
    confirmation = decryptionAES(encrypted_confirmation, sym_key)
    if confirmation != "Send the email":
        print("Error")
        return
   
    # format and encrypt email to send
    send_email = format_email(username)
    encrypted_email = encryptionAES(send_email.encode("utf-8"), sym_key)
    client_socket.send(encrypted_email)
   
    # email has been sent
    print("The message is sent to the server.")


# view_inbox_subprotocol
# view the inbox list from the server
# params: client_socket, sym_key
# return: none
def view_inbox_subprotocol(client_socket, sym_key):
        # Client Side: Receive the encrypted inbox list
    encrypted_inbox = client_socket.recv(1024)


    # Decrypt the inbox list
    decrypted_inbox = decryptionAES(encrypted_inbox, sym_key)


    # Display the inbox list
    if decrypted_inbox == "":
        print("No emails found in the inbox.")
    else:
        print(decrypted_inbox)




# view_email_subprotocol
# view the email content from the server
# params: client_socket, sym_key
# return: none
def view_email_subprotocol(client_socket, sym_key):
        # Client Side: Receive the encrypted email content
    encrypted_request = client_socket.recv(1024)


    # Decrypt the email content
    request = decryptionAES(encrypted_request, sym_key)


    if request == "the server request email index":
        # Ask user for input
        index = input("Enter the email index you wish to view: ")


        # Send the users encrypted index to the server
        encrypted_index = encryptionAES(index.encode("utf-8"), sym_key)
        client_socket.send(encrypted_index)


        # Receive the encrypted email content
        encrypted_email_content = client_socket.recv(1024)


        # Decrypt the email content
        email_content = decryptionAES(encrypted_email_content, sym_key)


        # Display email content
        print("\n" + email_content)
    else:
        print("Unexpected server response: " + request)


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
            print(menu, end=" ", flush = True)
             
            # get user choice
            sys.stdin.flush()
            sys.stdout.flush()
            choice = input()
             
            # encrypt and send choice
            encrypted_choice = encryptionAES(choice.encode("utf-8"), sym_key)
            client_socket.send(encrypted_choice)
             
            # Call function based on user choice
            if choice == '1':
                send_email_subprotocol(client_socket, sym_key, username)
 
            elif choice == '2':
                view_inbox_subprotocol(client_socket, sym_key)


            elif choice == '3':
                view_email_subprotocol(client_socket, sym_key)


            elif choice == '4':
                print("The connection with the server has been terminated.")
                break
                 
    # Close the client socket
    client_socket.close()


# run client
if __name__ == "__main__":
    server_ip = input("Enter the server ip: ")
    server_port = 13000
    start_client(server_ip, server_port)
