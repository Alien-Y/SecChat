import sys
import time
import socket
import threading
import rsa
from cryptography.fernet import Fernet



# animate loading
def animate(message, ending_message, waiting_time):
    time.sleep(0.5)
    for c in (['......','...........','...............','.................... ']):
        sys.stdout.write(f'\r{message}' + c)
        sys.stdout.flush()
        time.sleep(waiting_time)
    print(ending_message + '\n')



# configuring port and ip 
HOST = '127.0.0.1'
PORT = 12345

class ClientNode:
    def __init__(self):
        # Configuring Socket
        self.node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.node.connect((HOST, PORT))  # connect to server

        # session key
        self.sessionKey = None  

        # public-private keys for Digital signature
        self.publicKey = None
        self.privateKey = None

        # server public key
        self.serverPublicKey = None


    # METHODS:


    # generate public-private keys
    def generate_public_private_keys(self):
        self.publicKey, self.privateKey = rsa.newkeys(1024)
        return 'Successed!.'

    
    # create digital signiture
    def create_digital_signature(self, message):
        signature = rsa.sign(message, self.privateKey, 'SHA-512')
        return signature


    # verify digital signature
    def verify_signiture(self, message, signature):
        return rsa.verify(message, signature, self.serverPublicKey)


    # genereate session key
    def generate_session_key(self):
        self.sessionKey = Fernet.generate_key() 
        return 'Successed!.'


    # get server encryption key
    def receive_server_public_key_then_store_it(self):
        serverPublicKey_n = self.node.recv(1024).decode()
        serverPublicKey_e = self.node.recv(1024).decode()
        self.serverPublicKey = rsa.PublicKey(int(serverPublicKey_n), int(serverPublicKey_e))
        return 'Successed!.'


    # send the encryption session key to the server
    def send_session_key_to_server(self):
        encSessionKey = rsa.encrypt(str(self.sessionKey.decode()).encode(), self.serverPublicKey)
        self.node.send(encSessionKey)
        response = self.receive_message()   # receive server response
        # return response
        return 'Accepted!.'

    
    # send public key to the server
    def send_public_key_to_server(self):
        self.node.send(str(self.publicKey.n).encode())
        self.node.send(str(self.publicKey.e).encode())
        return 'Successed!.'

    
    # send a message
    def send_message(self, message):
        encMessage = rsa.encrypt(message.encode(), self.serverPublicKey)
        signature = self.create_digital_signature(encMessage)
        self.node.send(encMessage)
        self.node.send(signature)


    # receive a message
    def receive_message(self):
        encMessage = self.node.recv(1024)
        signature = self.node.recv(1024)
        if self.verify_signiture(encMessage, signature):
            decMessage = Fernet(self.sessionKey).decrypt(encMessage.decode())
            return decMessage.decode()
        else:   
            # TODO: throw an exception
            print('Signature could not be verified!.')
            return False

    
    # listen to all responses from server
    def listener(self):
        while True:
            print(self.receive_message())


    # login method
    def login(self):
        number = input(self.receive_message())
        self.send_message(number)

        password = input(self.receive_message())
        self.send_message(password)

        # get response from server
        response = self.receive_message()

        print(response)
        
        if response == 'Registerd Successfully!.':  # registering as a new user
            return True

        elif response == 'Logged in Successfully!.':  # login successed
            return True

        else:   # incorrect credentials
            return False
            

    # main method
    def main(self):
        # opan a thread for receiving messages
        always_receive = threading.Thread(target=self.listener)
        always_receive.start()

        while True:
            reply = input()
            self.send_message(reply)
            
            

animate('Connecting to the server', 'Successed!.', 0.5)
client = ClientNode()

animate('Getting server public key', client.receive_server_public_key_then_store_it(), 0.25)

animate('Generating public-private keys', client.generate_public_private_keys(), 0.3)

animate('Sending public key to the server', client.send_public_key_to_server(), 0.2)

animate('Generating session key', client.generate_session_key(), 0.2)

animate('Sending session key to the server', 'Accepted!.', 0.3)
client.send_session_key_to_server()

if client.login():  # login successed
    client.main()   # run main method