import socket 
import threading 

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

    print(server_ip)

    # close socket and return local ip
    s.close()
    return server_ip

# handle_client
# process of handling client connection. calls subprotocols to handle client requests.
# parameters: client_socket. The socket connection between server and client.
# returns: none
def handle_client(client_socket, client_address):

    # temporary client handling!!!!!!

    client_socket.send(b"Hello from the server!")

    client_message = client_socket.recv(1024).decode("utf-8")
    print("Received from client: ", client_message)

    client_socket.close()

# start_server
# configure server to listen for connection on port 13000 and machine ip 
# param: none
# returns: none
def start_server():
    # Get server machine ip
    server_ip = get_server_ip()

    print("Server started on IP: ", server_ip)

    # Create a socket and bind to the machine ip and port 13000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, 13000))  
    server_socket.listen(5)

    print("Listening on ", server_ip, ":13000 for incoming connections...")

    # Accept incoming client connections
    while True:
        # Accept incoming client connections
        client_socket, client_address = server_socket.accept()
        
        # Handle each client connection in a new thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

start_server()







                      