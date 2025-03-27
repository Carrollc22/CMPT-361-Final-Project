import os
import json

from Crypto.PublicKey import RSA

def generate_keys(keySize = 2048):

  """
  Generates a public/ private key pair using 2048 bits key length 

  param: keySize: The size of the key to generate (bits)
  return: The public and private key
  """

  key = RSA.generate(keySize)
  private_key = key.export_key()
  public_key = key.publickey().export_key()
  return private_key, public_key

def save_keys(key_data, filename):
  
  """
  Saves the public and private key to a file

  param: key_data: The key data to save
  param: filename: The name of the file to save the key to
  return: None
  """

  with open(filename, 'wb') as file:
    file.write(key_data)

def main():
    
    """
    Generates keys for the server and clients and saves them to their respective files

    param: None
    return: None
    """

    # Server keys
    server_private, server_public = generate_keys()
    save_keys(server_private, "Server/server_private.pem")
    save_keys(server_public, "Server/server_public.pem")
    save_keys(server_public, "Client/server_public.pem")

    # Client keys
    for i in range(1, 6):
        client_name = f"client{i}"
        
        # Generate key pair
        private_key, public_key = generate_keys()
        
        # Save keys
        save_keys(private_key, f"Client/{client_name}_private.pem")
        save_keys(public_key, f"Client/{client_name}_public.pem")
        save_keys(public_key, f"Server/Client{i}/{client_name}_public.pem")
