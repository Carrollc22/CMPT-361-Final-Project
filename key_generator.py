import os
import json

from Crypto.PublicKey import RSA

  # generate_keys
  # Generates a public/ private key pair using 2048 bits key length 
  # params: keySize: The size of the key to generate (bits)
  # return: The public and private key
def generate_keys(keySize = 2048):

  # Generate a new RSA key object with the specified key size
  key = RSA.generate(keySize)

  # Export the private key 
  private_key = key.export_key()

  # Extract and export the public key t
  public_key = key.publickey().export_key()
  return private_key, public_key
  
  # save_keys
  # Saves the public and private key to a file
  # params: key_data, filename
  # return: None
def save_keys(key_data, filename):

  # Open file save the key data
  with open(filename, 'wb') as file:
    file.write(key_data)

# main
# Generates keys for the server and clients and saves them to their respective files
# params: None
# return: None
def main():

    # Generages server key pair
    server_private, server_public = generate_keys()

    # Save server private key to Server directory
    save_keys(server_private, "Server/server_private.pem")

    # Save server public key to Server and Client directories

    # Save to server for own public key refernce
    save_keys(server_public, "Server/server_public.pem")

    # Save to client for encyption
    save_keys(server_public, "Client/server_public.pem")

    # Generate keys for clients and save them
    for i in range(1, 6):
        client_name = f"client{i}"
        
        # Generate key pair for each client
        private_key, public_key = generate_keys()
        
        # Save keys to directories
        # Save private key to Client directory
        save_keys(private_key, f"Client/{client_name}_private.pem")

        # Save public key to Client directory for reference
        save_keys(public_key, f"Client/{client_name}_public.pem")

        # Save public key to Server directory for encryption
        save_keys(public_key, f"Server/Client{i}/{client_name}_public.pem")
