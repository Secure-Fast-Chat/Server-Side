import json
import struct
import sys
import DatabaseRequestHandler
import selectors
from nacl.public import PrivateKey, Box
from db import checkIfUsernameFree, createUser, login

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

    def __init__(self,conn_socket,status,request,sel):
        """Constructor Object

        :param conn_socket: Socket which has a connection with client
        :type conn_socket: socket.socket
        :param task: Task to do. It can have values: login, signup, send_message
        :type task: str
        :param request: Content to send to server
        :type request: str
        """
        self.status = status
        self.socket = conn_socket
        self.request_content = request
        self._data_to_send = b''
        self.sel = sel
        self.privateKey = ""
        self.username = "" # Need this to keep track of whom we are signing up etc

    def _send_data_to_client(self):
        """ Function to send the string to the client. It sends content of _send_data_to_client to the client

        """
        left_message = self.sel.data["box"].encode(self._data_to_send)

        while left_message:
            bytes_sent = self.socket.sendall(left_message)
            # left_message = left_message[bytes_sent:]

        return

    def _recv_data_from_client(self,size):
        """ Function to recv data from client. Stores the bytes recieved in a variable named _recvd_msg.

        :param size: Length of content to recieve from server
        :type size: int
        """

        self._recvd_msg = self.sel.data["box"].decode(self.socket.recv(size))
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
        self._recv_data_from_client(2) # TODO: This only works when client makes the first request, what about when we are sending the message
        packed_proto_header = self._recvd_msg
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        self._recv_data_from_client(json_header_length)
        obj = self._recvd_msg
        json_header = json.loads(obj.decode(ENCODING_USED))
        request = json_header["request"]
        content_len = json_header['content-length']
        self._recv_data_from_client(content_len)
        content_obj = self._recvd_msg
        content = json.loads(content_obj.decode(ENCODING_USED))
        if(request == "signupuid"):
            print("request is signupuid")
            self._process_signup_uid(content)
        if(request == "signuppass"):
            print("request is signuppass")
            self._process_signup_pass(content["username"])
        if(request == "login"):
            ##!!
            print("request is login")
            ##!!
            self._process_login(content)
    
    def keyex(self)->str:
        """Does key exchange. First waits for request from the client, then sends a response with its own public key. Returns a string containing the public key of the client

        :return: public key of the client
        :rtype: str
        """
        self._recv_data_from_client(2) # TODO: This only works when client makes the first request, what about when we are sending the message
        packed_proto_header = self._recvd_msg
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        self._recv_data_from_client(json_header_length)
        obj = self._recvd_msg
        json_header = json.loads(obj.decode(ENCODING_USED))
        request = json_header["request"]
        if(request == "keyex"):
            clientPublicKey = json_header['key']
            publickey = self.request_content['key']
            jsonheader = {
                "byteorder": sys.byteorder,
                "request" : 'keyex',
                "key": publickey,
                "content-encoding" : ENCODING_USED,
                
            }
            encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
            proto_header = struct.pack('>H',len(encoded_json_header))
            # Command to use for unpacking of proto_header: 
            # struct.unpack('>H',proto_header)[0]
            self._data_to_send = proto_header + encoded_json_header # Not sending any content since the data is in the header
            self._send_data_to_server()
            return clientPublicKey
 
    def _process_login(self, uid):
        ## Pending Imlementation
        #Required: check_login_uid returns token if uid is valid, else returns 0
        uid_success = DatabaseRequestHandler.check_login_uid(uid)
        ##
        if( uid_success != 0 ):
            self._data_to_send = self._successfully_found_login_uid(uid_success)
            self._send_data_to_client()
            packed_proto_header = self.socket.recv(2)
            json_header_length = struct.unpack('>H', packed_proto_header)[0]
            obj = self.socket.recv(json_header_length)
            json_header = json.loads(obj.decode(ENCODING_USED))
            request = json_header["request"]
            content_len = json_header['content-length']
            content_obj = self.socket.recv(content_len)
            content = json.loads(content_obj.decode(ENCODING_USED))
            pwd = content
            ## Pending Implementation
            #Required: check_login_pwd returns 1 if matched successfully, else returns 0
            pwd_success = DatabaseRequestHandler.check_login_pwd(uid, pwd)
            ##
            if(pwd_success == 1):
                self.status = "logged_in"
                self._data_to_send = self._login_successful()
                self._send_data_to_client()
            else:
                self._data_to_send = self._login_failed()
                self._send_data_to_client()
        else:
            self._data_to_send = self._login_uid_not_found()
            self._send_data_to_client()
        
    def _login_failed(self):
        return struct.pack('>H', 1)

    def _login_successful(self):
        return struct.pack('>H', 0)

    def _login_uid_not_found(self):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "uid_found": 0,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header + encoded_json_header

    def _successfully_found_login_uid(self, token):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "uid_found": 1,
            "logintoken": token,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header + encoded_json_header

    def _signup_failed():
        return struct.pack('>H',2)
    
    def _successfully_signed_up():
        return struct.pack('>H',1)

    def _process_signup_uid(self,uid):
        ## Pending Implementation
        #Required: checkuid returns key, if uid is available to be ujed, else returns 0
        uid_free = checkIfUsernameFree(uid)
        ##
        if not uid_free:
            self._data_to_send = self._signup_uid_not_avaible()
            self._send_data_to_client()
        else:
            self._data_to_send = self._signup_uid_available() 
            self._send_data_to_client()
            #Storing uid in socket's data
            self.request_content["uid"] = uid
            self.processTask() #Immediately wait for next message, which would contain the password
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
    
    def _signup_uid_available(self):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "availability": 1,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header + encoded_json_header
    
    def _process_signup_pass(self, encrypted_pass:str):
        """Process the command for signing up the user and storing the password

        :param encrypted_pass: The encoded password
        :type encoded_pass: str
        :param client_public_key: Public key of the client 
        :type key: str
        """
        box = self.sel.data["box"]
        password = box.decrypt(encrypted_pass)
        success = createUser(self.username, password)
        if success:
            self._data_to_send = self._successfully_signed_up()
            self._send_data_to_client()
        else:
            self._data_to_send = self._signup_failed()
            self._send_data_to_client()
