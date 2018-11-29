#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''Project:

# #     ##      ##           ##     ###     ##      # #     ###     ##
# #     # #     # #         #       #       # #     # #     #       # #
# #     # #     ##           #      ##      ##      # #     ##      ##
# #     # #     #             #     #       # #     # #     #       # #
###     ##      #           ##      ###     # #      #      ###     # #

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

def find_iface_ip2():
    return socket.gethostbyname(socket.gethostname())

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
'''################# P2P SERVER CLASS OBJECT DEFINED #################'''
class P2PSocketServer(socket.socket):
    def __init__(self, \
                IPServer=str('127.0.0.1'), \
                PortServer=int(0), \
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
            isinstance(IPv4Address(IPServer), IPv4Address)
            self.P2P_IPServer = IPServer
        except AddressValueError as ErrorMessage:
            print(ErrorMessage)

        try:
            isinstance(PortServer, int)
            isinstance(MaxBuffer, int)
            self.P2P_PortServer = PortServer
            self.P2P_SocketServer = (IPv4Address(IPServer).compressed, \
                                    self.P2P_PortServer)
            self.P2P_SocketMaxBuffer = MaxBuffer
        except TypeError as ErrorMessage:
            print(ErrorMessage)

        '''#################################################'''
        '''A Centralized list of Clients and Exchanged Datas
            are stocked in Server's Memory here:'''
        self.P2P_Clients = [] # [(self.P2P_IPServer, self.P2P_PortServer)]
        self.P2P_AllMemory = [] # a list of bytearrays # 0th would be data sent?

        '''#######################'''
        '''Setting Default Timeout'''
        if socket.getdefaulttimeout() != None:
            socket.setdefaulttimeout(None)

        '''Binding created sockets:
        By precaution, i manually reserved port 14 both tcp/udp
        for my_py_server service in /etc/services file.'''
        '''Creating bidirectional udp connectors for mutual communication'''
        self.bind(self.P2P_SocketServer)

    '''#######################################################'''
    '''## Once Structure Generated, Connection starts with: ##'''
    def startConnection(self,IPClient=str(),PortClient=int()):
        try:
            isinstance(IPv4Address(IPClient), IPv4Address)
            isinstance(PortClient, int)
            SocketClient = (IPv4Address(IPClient).compressed, PortClient)
            self.connect(SocketClient)
            self.P2P_Clients.append(SocketClient)
        except AddressValueError as ErrorMessage:
            print(ErrorMessage)

    '''#################################################'''
    '''To Safely Control Interruption of the Connection:'''
    def stopConnection(self):
        pass

'''#####################################################################'''
'''############### THREADING CLASSES FOR THE SERVER-SIDE ###############'''
'''NOTE:    Difference to consider is:
            Although Peer2Peer, Server remains central,
            and susceptible of having multiple connections,
            that's why a different class specifying sendTo/recvFrom
            details are needed to be defined.
    NOTE2:  One could want though clients would be connected too.
            That is not my case for now. If so, use only Server Classes
            for generating Connections.(cf. further details)'''
class ListenToLocalServer(threading.Thread):
    def __init__(self, \
                Socket=P2PSocketServer(), \
                Data=bytes(), \
                Memory=bytearray(), \
                MaxBuffer=int()#, \
                #LogFile=\
                ):
        threading.Thread.__init__(self)
        self.ConnectionSocket = Socket
        self.ConnectionData = Data
        self.ConnectionMemory = Memory
        self.ConnectionMaxBuffer = self.ConnectionSocket.P2P_SocketMaxBuffer
        self.HeaderClient = str()

        self.ConnectionSocket.P2P_AllMemory.append(self.ConnectionMemory)
        self.ConnectionLogFile = str(getcwd()+'/Log'+self.getName()) #enumerate...
        #Thread's name has to be fixed for client given..
        #otherwise when session changes, buffering changes too.
        #self.setName(self.ConnectionSocket.P2P_Clients.index(...))
    '''###########################################'''
    '''## Automated Threading-Recv Function is: ##'''
    def recv(self, \
            recvSocket=P2PSocketServer(), \
            recvData=bytes(), \
            recvMemory=bytearray(), \
            recvMaxBuffer=int()):
        with open(self.ConnectionLogFile, 'ab', buffering=1) as logFile:
            recvData, self.HeaderClient = recvSocket.recvfrom(recvMaxBuffer)
            logFile.write(recvData+b'\n')
            recvData, self.HeaderClient = bytes(recvData), \
                                            str(self.HeaderClient[0]+':    ')
            recvMemory.extend(recvData+b'\n')
            print(self.HeaderClient+recvData.decode('utf-8'))

    '''#############################################'''
    '''#### Data recieved is logged into a File ####'''
    #generate a logFile for each client
    #no i cant make a separate function... recvData's value is lost once recieved
    #no it is not. but it is converted before.
    #and no need to reopen the file everytime...? no difference.
    #i ll see tomorrow.
    def logData(self, loggedData=bytes()): # think about buffering =0/1
        with open(self.ConnectionLogFile, 'ab', buffering=1) as logFile:
            logFile.write(loggedData+b'\n')

    '''#############################################'''
    '''##### Main Function to begin Threading: #####'''
    def run(self):
        try:
            while self.ConnectionSocket._closed == False:
                self.recv(recvSocket=self.ConnectionSocket, \
                            recvData=self.ConnectionData, \
                            recvMemory=self.ConnectionMemory, \
                            recvMaxBuffer=self.ConnectionMaxBuffer)
                #self.logData(loggedData=self.ConnectionData)
        except KeyboardInterrupt:
            self.ConnectionSocket.close()

'''###################################################################'''
'''###################################################################'''
class AnswerToClient(threading.Thread):
    def __init__(self, \
                Socket=P2PSocketServer(), \
                #Client=tuple() # how to know who i am answering?
                ):
        threading.Thread.__init__(self)
        self.ConnectionSocket = Socket
        self.ConnectionClient = Socket.P2P_Clients[0] # Client
        #self.setName(self.ConnectionSocket.P2P_Clients.index(...))

    '''###########################################'''
    '''## Automated Threading-Send Function is: ##'''
    def send(self, \
            sendSocket=P2PSocketServer(), \
            sendData=str(), \
            sendClient=tuple()):
        sendSocket.sendto(sendData.encode('utf-8'),sendClient)

    '''#############################################'''
    '''##### Main Function to begin Threading: #####'''
    def run(self):
        try:
            while self.ConnectionSocket._closed == False:
                self.send(sendSocket=self.ConnectionSocket, \
                        sendData=input(), \
                        sendClient=self.ConnectionClient)
        except KeyboardInterrupt:
            self.ConnectionSocket.close()
'''###################################################################'''
'''###################################################################'''
