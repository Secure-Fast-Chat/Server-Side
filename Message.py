import json
import struct
import sys

PROTOHEADER_LENGTH = 2 # to store length of protoheader
ENCODING_USED = "utf-8" # to store the encoding used
                        # The program uses universal encoding

class Message:
    """This is the class to handle Encryption of messages. The format in which the message is sent to client is determined in this class

    :param task: Task to be done. It can have the values signup, login, send_message
    :type task: str
    :param socket: The socket used for connection with Server
    :type socket: socket.socket
    :param request_content: Content to include in the request to send to server
    :type request_content: dict
    :param _data_to_send: Contains the data to send to the server
    :type _data_to_send: bytes
    :param _recvd_msg: Content received from server is stored here
    :type _recvd_msg: bytes
    """

    def __init__(self,conn_socket,task,request):
        """Constructor Object

        :param conn_socket: Socket which has a connection with client
        :type conn_socket: socket.socket
        :param task: Task to do. It can have values: login, signup, send_message
        :type task: str
        :param request: Content to send to server
        :type request: str
        """
        self.task = task
        self.socket = conn_socket
        self.request_content = request
        self._data_to_send = b''

    def _send_data_to_client(self):
        """ Function to send the string to the client. It sends content of _send_data_to_client to the client

        """
        left_message = self._data_to_send
        while left_message:
            bytes_sent = self.socket.send(left_message)
            left_message = left_message[bytes_sent:]
        return

    def _recv_data_from_client(self,size):
        """ Function to recv data from client. Stores the bytes recieved in a variable named _recvd_msg.

        :param size: Length of content to recieve from server
        :type size: int
        """

        self._recvd_msg = self.socket.recv(size)
        return

    def _json_encode(self, obj, encoding):
        """Function to encode dictionary to bytes object

        :param obj: dictionary to encode
        :type obj: dict
        :param encoding: Encoding to use
        :type encoding: str
        :return: Encoded obj
        :rtype: bytes"""

        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _json_decode(self, obj, encoding):
        """Function to decode bytes object to dictionary

        :param obj: Encoded json data
        :type obj: bytes
        :param encoding: Encoding used
        :type encoding: str
        :return: Decoded json object
        :rtype: json"""

        return json.load(obj.decode(encoding), ensure_ascii=False)

    def processTask(self):
        """ Processes the task to do

        :return: Returns int to represent result of the process. The details of return values are given in the corresponding functions handling the actions.
        :rtype: int
        """
        packed_proto_header = self.socket.recv(2)
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        obj = self.socket.recv(json_header_length)
        json_header = json.loads(obj.decode(ENCODING_USED))
        request = json_header["request"]
        content_len = json_header['content-length']
        content_obj = self.socket.recv(content_len)
        content = json.loads(content_obj.decode(ENCODING_USED))
        if(request == "signupuid"):
            self._process_signup_uid(content)
            

    def _process_signup_uid(self,uid):
        ## Pending Implementation
        #Required: checkuid returns key, if uid is available to be used, else returns 0
        uid_check = checkuid(uid)
        ##
        if(uid_check == 0):
            self._data_to_send = self._signup_uid_not_avaible()
            self._send_data_to_client()
        else:
            key = uid_check
            self._data_to_send = self._signup_uid_available(key) 
            self._send_data_to_client()
        return

    def _signup_uid_not_available(self):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "availability": 0,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header + encoded_json_header
    
    def _signup_uid_available(self, key):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "availability": 1,
            "key": key,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header + encoded_json_header