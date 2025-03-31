import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import datetime
import json
import os


MENU = "\nSelect the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\nchoice:"
received_nonces = []


# handle_received_email
# split the received email into individual components, print confirmation message, and add timestamp
# param: recv_email
# return: formatted_email, destinations, title
def handle_received_email(recv_email):
    # split by each line
    lines = recv_email.splitlines()
   
    # get components
    username = lines[0].split(":")[1].strip()  
    destinations = lines[1].split(":")[1].strip()  
    title = lines[2].split(":")[1].strip()  
    content_length = int(lines[3].split(":")[1].strip())
    # rest of message is content
    content = "\n".join(lines[4:]).strip()


    # server confirmation
    print(f"An email from {username} is sent to {destinations} has a content length of {content_length}")


    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")


    # format with date and time
    formatted_email = f"From: {username}\n" \
                      f"To: {destinations}\n" \
                      f"Time and Date: {current_datetime}\n" \
                      f"Title: {title}\n" \
                      f"Content Length: {content_length}\n" \
                      f"{content}"
    return formatted_email, destinations, title

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
# decrypt the incoming message and save nonce
# Parameters: encrypted_data, key
# Returns: decrypted_data.decoode
def decryptionRSA(encrypted_data, private_key):
    # extract nonce from message
    nonce = encrypted_data[:16]  
    # check nonce
    if nonce in received_nonces:
        return "playback attack detected"
    else:
        received_nonces.append(nonce)


    encrypted_message = encrypted_data[16:]


    # Init cipher with private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
   
    # Decrypt data
    decrypted_data = cipher_rsa.decrypt(encrypted_message)
   
    # return decoded data
    return decrypted_data.decode('utf-8')


# decryptionAES
# decrypt the incoming message and save nonce
# Parameters: encrypted_data, key
# Returns: unpadded_data.decoode
def decryptionAES(encrypted_data, sym_key):
    # extract nonce from message
    nonce = encrypted_data[:16]  
    #check nonce
    if nonce in received_nonces:
        return "playback attack detected"
    else:
        received_nonces.append(nonce)
    encrypted_message = encrypted_data[16:]


    # create an AES cipher object with the key in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)


    decrypted_data = cipher.decrypt(encrypted_message)


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

# handle_send_email
# send the email to the server
# params: client_socket, sym_key, username
# return: none
def handle_send_email(client_socket, sym_key, username):
    # send email protocol
    # let client know server is ready for email
    message = encryptionAES("Send the email".encode("utf-8"), sym_key)
    client_socket.send(message)

    # receive email
    recv_encrypt_email = client_socket.recv(1024)
    recv_email = decryptionAES(recv_encrypt_email, sym_key)


    # format and get partial components
    formatted_email, destinations, title = handle_received_email(recv_email)


    # for each valid recipient of the email write email to file in directory
    recipients = destinations.split(";")
    for i in recipients:
        if os.path.exists(f"Server/{i.strip()}"):
            with open(f"Server/{i.strip()}/{username}_{title.replace(' ', '_')}.txt", 'w') as file:
                file.write(formatted_email)




# handle_sort_emails
# sort the emails in the inbox by date and time
# params: username
# return: sorted_emails. The list of emails sorted by date and time
def handle_sort_emails(username):

    # Fetch inbox path (using the capitalized username)
    inbox_path = f'Server/{username}/'

    # Check if the inbox exists for the client
    if os.path.exists(inbox_path):
        emails = [f for f in os.listdir(inbox_path) if f.endswith('.txt')]  # List .txt files


    sorted_emails = []


    for file in emails:


        sender = ""
        date_time = ""
        title = ""
        # Extract the email's components
        with open(os.path.join(inbox_path, file), 'r') as email_file:
            lines = email_file.readlines()
           
            #Parse each line and split at the colon
            for line in lines:
                line = line.strip()
                # Parse From
                if line.startswith("From: "):
                    sender = line[line.find(":")+ 1:].strip()
                # Parse Time and Date
                elif line.startswith("Time and Date:"):
                    date_time = line[line.find(":")+1:].strip()
                # Parse Title
                elif line.startswith("Title:"):
                    title = line[line.find(":")+1:].strip()


            sorted_emails = sorted_emails[::-1]
           
            # Append to sorted_emails list
            sorted_emails.append([date_time, sender, title, file])


    return sorted_emails


# handle_view_inbox
# view the inbox list from the server
# params: client_socket, sym_key, username
# return: none
def handle_view_inbox(client_socket, sym_key, username):
   
    # Get sorted emails
    sorted_emails = handle_sort_emails(username)
   
    # Fetch inbox path (using the capitalized username)
    inbox_path = f'Server/{username}/'


    # Check if the inbox exists for the client
    if os.path.exists(inbox_path):
        emails = [f for f in os.listdir(inbox_path) if f.endswith('.txt')]  # List .txt files

        if emails:
            print(f"Client {username}'s inbox contents: ")
            for email in emails:
                print(email)


            # Formatted headers for the inbox list
            headers = "Index\tFrom\t\tDateTime\t\t\tTitle\n"
           
            #Format emails with index
            for i, email in enumerate(sorted_emails, 1):
                date_time, sender, title, _ = email
                headers += f"{i}\t{sender}\t\t{date_time}\t{title}\n"

            # Encrypt and send inbox list to the client
            encrypted_inbox = encryptionAES(headers.encode("utf-8"), sym_key)
            client_socket.send(encrypted_inbox)

        else:
            # If no emails exist in the inbox, send an encrypted empty message
            empty_message = ""
            encrypted_inbox = encryptionAES(empty_message.encode("utf-8"), sym_key)
            client_socket.send(encrypted_inbox)
    else:
        # If no inbox folder exists for the client, send an encrypted empty message
        empty_message = ""
        encrypted_inbox = encryptionAES(empty_message.encode("utf-8"), sym_key)
        client_socket.send(encrypted_inbox)


    print(f"Client {username} selected: View inbox")




# handle_view_email
# view the email content from the server
# params: client_socket, sym_key, username
# return:
def handle_view_email(client_socket, sym_key, username):
    # Send request for email index
    message = encryptionAES("the server request email index".encode("utf-8"), sym_key)
    client_socket.send(message)

    # Receive the encrypted index from client
    encrypted_index = client_socket.recv(1024)
    index = decryptionAES(encrypted_index, sym_key)
    if index == "playback attack detected":
        return "playback attack detected"
   
    # Get sorted emails
    sorted_emails = handle_sort_emails(username)
    i = int(index) - 1


    if 0 <= i < len(sorted_emails):


        # Get the filename directly from the sorted emails list
        filename = sorted_emails[i][3]  
       
        # Construct path and read file
        inbox_path = f"Server/{username}/"
        email_file_path = os.path.join(inbox_path, filename)
       
        with open(email_file_path, 'r') as file:
            email_content = file.read()
       
        # Encrypt and send email
        encrypted_content = encryptionAES(email_content.encode("utf-8"), sym_key)
        client_socket.send(encrypted_content)
       
        print(f"Email content sent to client {username}")
    else:
        # Invalid index
        error_message = "Invalid email index"
        encrypted_error = encryptionAES(error_message.encode("utf-8"), sym_key)
        client_socket.send(encrypted_error)
    return "success"






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
    if decrypted_data == "playback attack detected":
        print("playback attack detected")
        client_socket.close()
        return


    # Split
    username, password = decrypted_data.split(',')


    # validate with json file and get public key
    if validation(username, password):
        # generate sym key for future aes encrytion
        sym_key = get_random_bytes(32)
       
        # get user public key for rsa
        pem_file = f"Server/{username}/{username}_public.pem"


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
    if message == "playback attack detected":
        print("playback attack detected")
        client_socket.close()
        return


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
        if choice == "playback attack detected":
            print(choice)
            client_socket.close()
            return
   
        if choice == '1':
            handle_send_email(client_socket, sym_key, username)          
         
        elif choice == '2':
            handle_view_inbox(client_socket, sym_key, username)


        elif choice == '3':
            status = handle_view_email(client_socket, sym_key, username)
            if status == "playback attack detected":
                print(status)
                client_socket.close()
                return

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
    server_socket.bind((server_ip, 13000))  
    server_socket.listen(5)

    while True:
        # Accept incoming client connections
        client_socket, client_address = server_socket.accept()
       
       # fork the process 
        process = os.fork()

        # handle client in child process
        if process == 0:  
            # no longer need server socket
            server_socket.close() 
            handle_client(client_socket, client_address)
            # exit process when connection terminated
            os._exit(0) 
        else:
            # close socket socket in parent, client is running on child 
            client_socket.close()


if __name__ == "__main__":
     start_server()
