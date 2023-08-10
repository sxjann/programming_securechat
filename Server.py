import pickle
import socket
import threading
from typing import Tuple
import rsa
from Crypto.Cipher import AES

hostIP = socket.gethostname()    
port = 5555

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((hostIP,port))

server.listen()

clients=[]
nicknames=[]

server_symetric_key= pickle.dumps("This is the key!")  

def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message= client.recv(1024)
            broadcast(message) 
        except:
            index= clients.index(client)
            clients.remove(client)
            client.close()
            nickname=nicknames[index]
            broadcast(aes_encryption(f"{nickname} has Disconnected from the server \n"))
            nicknames.remove(nickname)

def aes_encryption(plain_text)->Tuple:
    cipher = AES.new(pickle.loads(server_symetric_key).encode('utf-8'), AES.MODE_EAX)   
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return pickle.dumps((ciphertext,nonce,tag))  

def main():
    while True:
        client, address= server.accept()

        client.send(pickle.dumps("NICK")) 
        nickname = pickle.loads(client.recv(1024))
        nicknames.append(nickname)
        clients.append(client)

        client.send(pickle.dumps("PUBLIC KEY")) 

        pickled_client_public_key = client.recv(1024) 

        client_public_key = pickle.loads(pickled_client_public_key)  

        encrypted_symetric_key= rsa.encrypt(server_symetric_key,client_public_key)  
        client.send(encrypted_symetric_key)
        
        broadcast(aes_encryption(f"{nickname} has connected to the server \n"))  

        thread= threading.Thread(target=handle, args=(client,))
        thread.start()


print("server is running...")
main()