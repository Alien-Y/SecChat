import sys
import threading
import pickle
import time
import datetime
import hashlib
import socket
import rsa
import uuid
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509 import CertificateBuilder
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers, RSAPrivateNumbers
# import certauth.certauth as ca
# from OpenSSL.SSL import FILETYPE_PEM
# from OpenSSL import rand
# from OpenSSL.crypto import (dump_certificate, X509, X509Name, PKey, TYPE_RSA, X509Req, dump_privatekey, X509Extension)


# animate loading
def animate(message, ending_message, waiting_time):
    time.sleep(0.5)
    for c in (['......', '...........', '...............', '.................... ']):
        sys.stdout.write(f'\r{message}'+c)
        sys.stdout.flush()
        time.sleep(waiting_time)
    print(ending_message+'\n')


# configuring port and ip
HOST = '127.0.0.1'
PORT = 12345

CA_HOST = '127.0.0.1'
CA_PORT = 54321


class ServerNode:
    def __init__(self):
        # Configuring Socket:
        #   socket.AF_INET means socket belong to IPV4 Family
        #   socket.SOCK_STREAM means connection configured using TCP Protocol
        self.node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.node.bind((HOST, PORT))   # bind port and ip
        # listen to incoming connections, 5: the maximum number of connections that can be queued for this socket
        self.node.listen(5)

        # Clients stuff
        self.clientsInfo = {}           # store clients numbers with passwords
        self.onlineClients = {}         # store online clients
        self.clientsSessionsKeys = {}   # store clients sessions keys
        self.clientsPublicKeys = {}     # store clients public keys for digital signature

        # PGP encryption stuff
        self.publicKey = None
        self.privateKey = None


    # METHODS:


    # generate public-private keys

    def generate_public_private_keys(self):
        self.publicKey, self.privateKey = rsa.newkeys(1024)

    # load clients credentials from client's text file:
    #   this method must be called when server starts,
    #       so data will be loaded to the runtime
    #       clientsInfo dictionary

    def load_clients_credentials(self):
        file_handler = open('clients/clients.txt', 'r')
        clientsInfo = file_handler.readlines()
        for clientInfo in clientsInfo:
            # split every line to client number and client password
            client_num, client_pass = clientInfo.strip().split(': ')
            # add these info to clientsInfo dictionary
            self.clientsInfo[client_num] = client_pass


    # save client message to client's messages text file

    def save_message(self, from_client, to_client, message):
        file_handler = open(f'messages/{from_client}.txt', 'a')
        current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_handler.write(
            f'A message sent to client {to_client} at {current_datetime}: {message}\n')
        file_handler.close()


    # save client info to clients text file

    def save_client_info(self, client_num, client_pass):
        file_handler = open('clients/clients.txt', 'a')
        file_handler.write(f'{client_num}: {client_pass}\n')
        file_handler.close()


    # get client messages

    def get_client_messages(self, connection):
        client_num = self.get_client_num(connection)    # get client number
        try:
            file_handler = open(f'messages/{client_num}.txt', 'r')
            file_content = file_handler.read()
            file_handler.close()
            return file_content
        except FileNotFoundError:
            return '\nNo messages yet!'


    # send server encryption key to client

    def send_public_key_to_client(self, connection):
        connection.send(str(self.publicKey.n).encode())
        connection.send(str(self.publicKey.e).encode())


    # get client encryption key

    def receive_client_session_key_then_store_it(self, connection):
        encClientSessionKey = connection.recv(1024)
        decClientSessionKey = rsa.decrypt(encClientSessionKey, self.privateKey)
        # store client session key
        self.clientsSessionsKeys[connection] = decClientSessionKey
        self.send_message(connection, 'Accepted!.')


    # get client public key

    def receive_client_public_key_then_store_it(self, connection):
        clientPublicKey_n = connection.recv(1024).decode()
        clientPublicKey_e = connection.recv(1024).decode()
        self.clientsPublicKeys[connection] = rsa.PublicKey(
            int(clientPublicKey_n), int(clientPublicKey_e))


    # create digital signiture

    def create_digital_signature(self, message):
        signature = rsa.sign(message, self.privateKey, 'SHA-512')
        return signature


    # verify digital signature

    def verify_signiture(self, connection, message, signature):
        return rsa.verify(message, signature, self.clientsPublicKeys[connection])


    # get client number from its connection

    def get_client_num(self, connection):
        keys_list = list(self.onlineClients.keys())
        values_list = list(self.onlineClients.values())
        return keys_list[values_list.index(connection)]


    # send a message to client:

    def send_message(self, connection, message):
        encMessage = Fernet(self.clientsSessionsKeys[connection]).encrypt(
            message.encode())  # encode: the message must be in bytes
        signature = self.create_digital_signature(encMessage)
        connection.send(encMessage)
        connection.send(signature)


    # receive messages from clients

    def receive_message(self, connection):
        encMessage = connection.recv(1024)
        signature = connection.recv(1024)
        if self.verify_signiture(connection, encMessage, signature):
            decMessage = rsa.decrypt(encMessage, self.privateKey)
            return decMessage.decode()
        else:
            # TODO: throw an exception
            print('Signature could not be verified!.')
            return False


    # close connection with a client

    def close_connection(self, connection):
        connection.close()


    # show all users on the server

    def show_users(self):
        print("\n---------------------------------- All Users On Server ----------------------------------")
        print("{:<8} {:<20}".format('Number', 'Password'))
        for key, value in self.clientsInfo.items():
            num, pass_ = key, value
            print("{:<8} {:<20}".format(num, pass_))
        print("-------------------------------------------------------------------------------------------\n")


    # login new clients

    def login_client(self, connection):
        # Request Username
        self.send_message(connection, '\nEnter Your Number: ')
        number = self.receive_message(connection)

        self.send_message(connection, '\nEnter Password: ')
        password = self.receive_message(connection)  # Request Password
        # Password hash using SHA256
        password = hashlib.sha256(str.encode(password)).hexdigest()

        # REGISTERATION PHASE:
        # If new user, register it in Hashtable Dictionary
        if number not in self.clientsInfo:
            self.clientsInfo[number] = password         # add user info
            self.onlineClients[number] = connection  # add client connection
            # save user info on server
            self.save_client_info(number, password)
            # send attention to client
            self.send_message(connection, 'Registerd Successfully!.')
            print(f'A new user has been registered with number: {number}')
            return True

        else:   # If already existing user, check if the entered password is correct
            if self.clientsInfo[number] == password:
                # add client connection
                self.onlineClients[number] = connection
                # send attention to client
                self.send_message(connection, 'Logged in Successfully!.')
                print(f'Connection Successed with User number: {number}')
                return True

            else:
                # send attention to client
                self.send_message(connection, 'Login Failed')
                print(
                    f'Connection denied with User number: {number}, Incorrect password entered')
                connection.close()
                return False


    # do chat with client

    def chat(self, connection):
        self.send_message(connection, '\nEnter client number: ')
        client_num = self.receive_message(connection)

        self.send_message(connection, '\nEnter message: ')
        message = self.receive_message(connection)

        if client_num in self.onlineClients.keys():     # check if user is connected to the server
            # send the message to desired client
            self.send_message(
                self.onlineClients[client_num], f'\nMessage received from client {self.get_client_num(connection)}: {message}')
            # save client message on server
            self.save_message(self.get_client_num(
                connection), client_num, message)
            # send attention to client
            self.send_message(
                connection, '\nYour message has been successfully sent!.')

        else:   # the client does not exist
            # send attention to client
            self.send_message(
                connection, '\nMessage was not sent! User does not exist on server.')


    # listen to messages from clients
    #   this method must run alltime

    def listener(self, connection):
        while True:
            options = "\n1- Send a message\n2- Show my messages\n3- Close connection with server\n\nChoose an option:\n"
            self.send_message(connection, options)

            # request option from client
            option = self.receive_message(connection)

            # send a message
            if option == str(1):
                self.chat(connection)

            # show client's messages
            if option == str(2):
                self.send_message(
                    connection, self.get_client_messages(connection))

            # close connection with client
            if option == str(3):
                self.close_connection(connection)


    # main method: deal with new connections

    def main(self):
        while True:
            # request connection
            client, address = self.node.accept()

            self.send_public_key_to_client(client)

            self.receive_client_public_key_then_store_it(client)

            self.receive_client_session_key_then_store_it(client)

            if self.login_client(client):
                # open a thread to receive messages from client
                always_receive = threading.Thread(
                    target=self.listener,
                    args=(client,)
                )
                always_receive.start()


###################################################################
################# when initializing the server: ###################

# initialize the server
server = ServerNode()
animate('Server is starting', 'Server started successfully!.', 1)

server.generate_public_private_keys()
animate('Generating public-private keys', 'Generated successfully!.', 0.5)

# load clients credentials
server.load_clients_credentials()
animate('Loading clients credentials', 'Loaded successfully!.', 0.5)

print('Server is runing now...\n')
# run server
server.main()
