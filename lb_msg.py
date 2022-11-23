import socket
import json
import struct
import sys
import random

SERVER_MAPPING = [
        ("127.0.0.1", 8001),
        ("127.0.0.1", 8002),
        # ("127.0.0.1", 8003),
        # ("127.0.0.1", 8004),
        # ("127.0.0.1", 8005),
    ]

LOGGED_CLIENTS = {}
SERVER_SOCKETS = {}
ENCODING_USED = 'utf-8'

class NameItYourself:
    """ Class for conversation over sockets

    :param socket: Connection Socket to talk on
    :type socket: socket.socket
    :param _msg_to_send: the message to send to client
    :type _msg_to_send: bytes
    """

    def __init__(self,socket):
        """ Constructor object

        :param socket: Connection socket
        :type socket: socket.socket
        """
        self.socket = socket

    def _json_encode(self, obj, encoding = ENCODING_USED):
        """Function to encode dictionary to bytes object

        :param obj: dictionary to encode
        :type obj: dict
        :param encoding: (Optional)Encoding to use
        :type encoding: str
        :return: Encoded obj
        :rtype: bytes"""

        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _getAvailableServerID(self):
        """ This function finds the server with least number of connections and returns the corresponding id.

        :return: The id of server to use
        :rtype: int
        """

        server = random.randint(0, len(SERVER_MAPPING)-1)
        print(f'Redirecting to server {server}')
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

        return SERVER_SOCKETS[self._getLsockHostPortFromID(server_id)]

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
        print(json_header)
        print(content)
        json_header['content-len'] = len(content)
        json_header['byteorder'] = sys.byteorder
        encoded_json_header = self._json_encode(json_header)
        protoheader = struct.pack(">H",len(encoded_json_header))
        self._msg_to_send = protoheader + encoded_json_header + content
        return

    def _readMessage(self):
        header_len = self.socket.recv(2)
        header_len = struct.unpack('>H', header_len)[0]
        obj = self.socket.recv(header_len)
        json_header = json.loads(obj.decode(ENCODING_USED))
        contentLength = json_header["content-length"]
        content = self.socket.recv(contentLength)
        return json_header, content
    
    def processTask(self):
        json_header, content = self._readMessage()
        request = json_header["request"]
        if request == "pls-relay":
            receiver_username = json_header["receiver"]
            serverSock = None
            if receiver_username in LOGGED_CLIENTS.keys():
                # Send a relay request to the corresponding server
                serverSock = self._getLsockHostPortFromID(LOGGED_CLIENTS[receiver_username])
            else:
                serverSock = self._getSocketFromID(self._getAvailableServerID())
            self._prepareMessage(json_header, content)
            serverSock.sendall(self._msg_to_send)
        if request == "new-login":
            pass





    def _send_data_to_client(self):
        """ Sends the content of _msg_to_send through the socket

        """

        self.socket.sendall(self._msg_to_send)

    def processClient(self):
        """ Function to redirect client

        """
        server_id = self._getAvailableServerID()
        host,port = self._getLsockHostPortFromID(server_id)
        header = {
                'host' : host,
                'port' : port
                }
        self._prepareMessage(header,encrypt = False)
        self._send_data_to_client()
