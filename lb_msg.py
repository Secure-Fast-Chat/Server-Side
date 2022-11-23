import socket
import sys

SERVER_MAPPING = {
        1 : ('localhost',8000)
        }

LOGGED_CLIENTS = {}
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

        server = 1
        print(f'Redirecting to server {server}')
        return server
    
    def _getLsockFromID(self,server_id):
        """ Get the listening socket details from id

        :return: Listening socket details as (host,port) tuple
        :rtype: tuple(str,int)
        """

        return SERVER_MAPPING[server_id]

    def _prepareMessage(header,content=b'',encrypt = True):
        """ Prepare the string to send from header and content and encrypt by default

        :param header: Json Header with important headers. content-len and byteorder are added to header in the function
        :type header: dict
        :param content: The content of the message(Optional,default = b'')
        :type content: bytes
        :param encrypt: If encryption is to be done(Optional, default = True)
        :type encrypt: bool
        """

        if encrypt:
            pass
        header['content-len'] = len(content)
        header['byteorder'] = sys.byteorder
        encoded_json_header = self._json_encode(header)
        protoheader = struct.pack(">H",len(encoded_json_header))
        self._msg_to_send = protoheader + encoded_json_header + content
        return

    def _send_data_to_client(self):
        """ Sends the content of _msg_to_send through the socket

        """

        self.socket.sendall(self._msg_to_send)

    def processClient(self):
        """ Function to redirect client

        """
        server_id = _getAvailableServerID()
        host,port = _getLsockFromID(server_id)
        json_header = {
                'host' : host,
                'port' : port
                }
        self._prepareMessage(json_header,encrypt = False)
        self._send_data_to_client()
