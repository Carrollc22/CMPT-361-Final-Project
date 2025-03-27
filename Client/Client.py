import socket

# start_client
# connects to server through known server ip and port
# params: server_ip, server_port. known ip and port addresses to start connection 
# return: none
def start_client(server_ip, server_port):
    # config socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((server_ip, server_port))

    # temporary server and client communication!!!

    welcome_message = client_socket.recv(1024).decode()
    print(welcome_message)

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
