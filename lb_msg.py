import socket
import json
import struct
import sys
import random

SERVER_MAPPING = [
        ("127.0.0.1", 8001),
        ("127.0.0.1", 8002),
        ("127.0.0.1", 8003),
        ("127.0.0.1", 8004),
        ("127.0.0.1", 8005),
    ]

LOGGED_CLIENTS = {} # username: (host, port)
SERVER_SOCKETS = {} # index: socket
ENCODING_USED = 'utf-8'
# STRATERGY = "round-robin"
NEXTSERVERID = 0 # Next server for round robin
SERVER_COUNT = [0 for i in SERVER_MAPPING] # The count of the number of clients on a server

class LoadBalancerMessage:
    """ Class for conversation over sockets

    :param socket: Connection Socket to talk on
    :type socket: socket.socket
    :param strategy: Loadbalancing algorithm to use
    :type strategy: str
    :param _msg_to_send: the message to send to client
    :type _msg_to_send: bytes
    :param sel:
    :type sel:
    """

    def __init__(self,socket, sel,strategy="random"):
        """ Constructor object

        :param socket: Connection socket
        :type socket: socket.socket
        """
        self.socket = socket
        self.strategy = strategy
        self.sel = sel
        self._json_header = None
        self._content = None
        self._proto_header = None
        self._recvd_data = b''
        self._data_to_send = b""

    def _json_encode(self, obj, encoding = ENCODING_USED):
        """Function to encode dictionary to bytes object

        :param obj: dictionary to encode
        :type obj: dict
        :param encoding: (Optional)Encoding to use
        :type encoding: str
        :return: Encoded obj
        :rtype: bytes"""

        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _getAvailableServerID(self, strategy):
        """ This function finds the server with least number of connections and returns the corresponding id.

        :return: The id of server to use
        :rtype: int
        """

        if strategy == "random":
            return self._getRandomServer()
        elif strategy == "round-robin":
            return self._getRoundRobinServer()
        elif strategy == "least-conn":
            return self._getLeastConnServer()

    def _getLeastConnServer(self):
        """This function implements the least connection server Distribution
        Returns the server_id with least number of connections
        
        :return: server id
        :rtype: int"""
        return SERVER_COUNT.index(min(SERVER_COUNT))

    def _getRoundRobinServer(self):
        """This function implements the round robin server Distribution
        
        :return: server id
        :rtype: int"""
        server = NEXTSERVERID
        NEXTSERVERID = (NEXTSERVERID + 1)%len(SERVER_MAPPING)
        return server

    def _getRandomServer(self):
        """This function implements the random server Distribution
        
        :return: server id
        :rtype: int"""
        server = random.randint(0, len(SERVER_MAPPING)-1)
        return server

    def _getLsockHostPortFromID(self,server_id):
        """ Get the listening socket details from id

        :return: Listening socket details as (host,port) tuple
        :rtype: tuple(str,int)
        """

        return SERVER_MAPPING[server_id]
    
    def _getSocketFromID(self,server_id):
        """ Get the listening socket from id

        :return: Listening socket details as (host,port) tuple
        :rtype: tuple(str,int)
        """

        return SERVER_SOCKETS[server_id]

    def _prepareMessage(self,json_header,content=b'', encrypt=True):
        """ Prepare the string to send from header and content and encrypt by default

        :param json_header: Json Header with important headers. content-len and byteorder are added to header in the function
        :type json_header: dict
        :param content: The content of the message(Optional,default = b'')
        :type content: bytes
        :param encrypt: If encryption is to be done(Optional, default = True)
        :type encrypt: bool
        """
        if encrypt:
            pass
        # print(json_header)
        # print(content)
        json_header['content-len'] = len(content)
        json_header['byteorder'] = sys.byteorder
        encoded_json_header = self._json_encode(json_header)
        protoheader = struct.pack(">H",len(encoded_json_header))
        self._msg_to_send = protoheader + encoded_json_header + content
        return

    def readFromSocket(self):
        """Returns the json_header and content of the message recieved
        """

        if not self._proto_header:
            self._recvd_data += self.socket.recv(2)
            if len(self._recvd_data) < 2:
                return 1
            else:
                self._proto_header = struct.unpack(">H",self._recvd_data)[0]
                self._recvd_data = b''
        if not self._json_header:
            header_len = self._proto_header
            self._recvd_data += self.socket.recv(header_len-len(self._recvd_data))
            if len(self._recvd_data) < self._proto_header:
                return 1
            else:
                self._json_header = json.loads(self._recvd_data.decode(ENCODING_USED))
                self._recvd_data = b''
        if not self._content:
            self._recvd_data += self.socket.recv(self._json_header['content-length']-len(self._recvd_data))
            if len(self._recvd_data) < self._json_header['content-length']:
                return 1
            self._content = self._recvd_data
            self.processTask()
            return 0

    
    def processTask(self):
        """Processes and redirects requests
        """
        json_header, content = self._json_header,self._content
        request = json_header["request"]
        if request == "pls-relay":
            print("got a message to relay")
            receiver_username = json_header["receiver"]
            serverSock = None
            if receiver_username in LOGGED_CLIENTS.keys():
                # Send a relay request to the corresponding server
                address = LOGGED_CLIENTS[receiver_username] 
                serverId = SERVER_MAPPING.index(address)
                serverSock = self._getSocketFromID(serverId) 
            else:
                serverSock = self._getSocketFromID(self._getAvailableServerID(self.strategy))
            self._prepareMessage(json_header, content)
            # print(f"Sending {self._msg_to_send} to {serverSock}")
            server_key = self.sel.get_key(serverSock)
            if 'to_send' not in server_key.data.keys():
                server_key.data['to_send'] = b''
            server_key.data['to_send'] += self._msg_to_send
        if request == "new-login":
            print(f"Load balancer New user logged in: {json_header['uid']}")
            LOGGED_CLIENTS[json_header["uid"]] = (json_header["host"], json_header["port"])
            SERVER_COUNT[SERVER_MAPPING.index((json_header["host"], json_header["port"]))]+=1
        if request == "user-logout":
            username = json_header["uid"]
            print(f"{username} logged out")
            if json_header["uid"] in LOGGED_CLIENTS.keys():
                SERVER_COUNT[SERVER_MAPPING.index(LOGGED_CLIENTS[json_header["uid"]])]-=1
                del LOGGED_CLIENTS[json_header["uid"]]
            pass

    def _send_data_to_client(self):
        """ Sends the content of _msg_to_send through the socket

        """

        self.socket.sendall(self._msg_to_send)

    def processClient(self):
        """ Function to redirect client

        """
        server_id = self._getAvailableServerID(self.strategy)
        host,port = self._getLsockHostPortFromID(server_id)
        header = {
                'host' : host,
                'port' : port
                }
        self._prepareMessage(header,encrypt = False)
        self._send_data_to_client()
