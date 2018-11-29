#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''Project:

# #     ##      ##           ##     #       ###     ###     ###     ###
# #     # #     # #         #       #        #      #       # #      #
# #     # #     ##          #       #        #      ##      # #      #
# #     # #     #           #       #        #      #       # #      #
###     ##      #            ##     ###     ###     ###     # #      #  

'''

import socket
import threading
from ipaddress import AddressValueError, IPv4Address
from os import getcwd

'''###################################################################'''
'''############# Defining practical & local functions: ###############'''
def find_iface_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    iface_ip = s.getsockname()[0]
    s.close()
    return iface_ip

def test_conn(Socket=socket.socket()):
    ''' not useful as a function apart but i must remember this one '''
    if Socket._closed == False:
        print('connection remains')
        return True
    else:
        print('connection lost')
        return False

toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])

'''###################################################################'''
'''################# P2P CLIENT CLASS OBJECT DEFINED #################'''
class P2PSocketClient(socket.socket):
    def __init__(self, \
                IPClient=str('127.0.0.1'), \
                PortClient=int(0), \
                MaxBuffer=int(0)):

        '''#########################################'''
        '''UDP Sockets' prototypes are created here:'''
        socket.socket.__init__(self, \
                                family=socket.AF_INET, \
                                proto=socket.IPPROTO_UDP, \
                                type=socket.SOCK_DGRAM)

        '''#############################################'''
        ''' Initial Arguments' Values are checked here: '''
        try:
            isinstance(IPv4Address(IPClient), IPv4Address)
            self.P2P_IPClient = IPClient
        except AddressValueError as ErrorMessage:
            print(ErrorMessage)

        try:
            isinstance(PortClient, int)
            isinstance(MaxBuffer, int)
            self.P2P_PortClient = PortClient
            self.P2P_SocketClient = (IPv4Address(IPClient).compressed, \
                                    self.P2P_PortClient)
            self.P2P_SocketMaxBuffer = MaxBuffer
        except TypeError as ErrorMessage:
            print(ErrorMessage)

        '''I will anticipate the code by asserting that
            clients know already the server (but i wont change
            functions' code for conformity):'''
        self.P2P_IPServer = '192.168.56.101'
        self.P2P_PortServer = 14
        self.P2P_SocketServer = (self.P2P_IPServer, \
                                    self.P2P_PortServer)

        '''#################################################'''
        '''A Centralized Buffer Stream within bytearray Memory
            is initialized here:'''
        self.P2P_SocketData = bytes()
        self.P2P_SocketMemory = bytearray()

        '''#######################'''
        '''Setting Default Timeout'''
        if socket.getdefaulttimeout() != None:
            socket.setdefaulttimeout(None)

        '''Binding created sockets:
        By precaution, i manually reserved port 14 both tcp/udp
        for my_py_server service in /etc/services file.'''
        '''Creating bidirectional udp connectors for mutual communication'''
        self.bind(self.P2P_SocketClient)

    '''#######################################################'''
    '''## Once Structure Generated, Connection starts with: ##'''
    def startConnection(self):#,IPServer=str(),PortServer=int()):
        #try:
        #    isinstance(IPv4Address(IPServer), IPv4Address)
        #    isinstance(PortServer, int)
        #    SocketServer = (IPv4Address(IPServer).compressed, PortServer)
        #    self.connect(SocketServer)
        #except AddressValueError as ErrorMessage:
        #    print(ErrorMessage)
        self.connect(self.P2P_SocketServer)
    '''#################################################'''
    '''To Safely Control Interruption of the Connection:'''
    def stopConnection(self):
        pass

'''#####################################################################'''
'''############### THREADING CLASSES FOR THE CLIENT-SIDE ###############'''
class ListenToLocalClient(threading.Thread):
    def __init__(self, \
                Socket=P2PSocketClient(), \
                Data=bytes(), \
                Memory=bytearray(), \
                MaxBuffer=int()):
        threading.Thread.__init__(self)
        self.ConnectionSocket = Socket
        self.ConnectionData = Data
        self.ConnectionMemory = Memory
        self.ConnectionMaxBuffer = self.ConnectionSocket.P2P_SocketMaxBuffer
        self.HeaderServer = str('SERVER        :    ')

        #if needed: for now, client dont.
        #self.ConnectionLogFile = str(getcwd()+'/LogServer.log')

    '''###########################################'''
    '''## Automated Threading-Recv Function is: ##'''
    def recv(self, \
            recvSocket=P2PSocketClient(), \
            recvData=bytes(), \
            recvMemory=bytearray(), \
            recvMaxBuffer=int()):
        recvData = bytes(recvSocket.recv(recvMaxBuffer))
        recvMemory.extend(recvData+b'\n')
        print(self.HeaderServer+recvData.decode('utf-8'))

    '''#############################################'''
    '''##### Main Function to begin Threading: #####'''
    def run(self):
        try:
            while self.ConnectionSocket._closed == False:
                self.recv(recvSocket=self.ConnectionSocket, \
                            recvData=self.ConnectionData, \
                            recvMemory=self.ConnectionMemory, \
                            recvMaxBuffer=self.ConnectionMaxBuffer)
        except KeyboardInterrupt:
            self.ConnectionSocket.close()

'''###################################################################'''
'''###################################################################'''
class AnswerToServer(threading.Thread):
    def __init__(self, \
                Socket=P2PSocketClient()):
        threading.Thread.__init__(self)
        self.ConnectionSocket = Socket

    '''###########################################'''
    '''## Automated Threading-Send Function is: ##'''
    def send(self, \
            sendSocket=P2PSocketClient(), \
            sendData=str()):
        sendSocket.send(sendData.encode('utf-8'))

    '''#############################################'''
    '''##### Main Function to begin Threading: #####'''
    def run(self):
        try:
            while self.ConnectionSocket._closed == False:
                self.send(sendSocket=self.ConnectionSocket,sendData=input())
        except KeyboardInterrupt:
            self.ConnectionSocket.close()
'''###################################################################'''
'''###################################################################'''
