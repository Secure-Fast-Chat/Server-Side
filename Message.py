import json
import struct
import sys
import DatabaseRequestHandler
import selectors
from nacl.public import PrivateKey, Box
from db import checkIfUsernameFree, createUser, db_login, storeMessageInDb, getE2EPublicKey
import startServer
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
        try:
            self.username = sel.data["username"] # Need this to keep track of whom we are signing up etc
        except:
            self.username = ""
        self.online = 0

    @classmethod 
    def fromSelKey(cls, selectorKey):
        status = 0
        socket = selectorKey.fileobj
        request_content=""
        _data_to_send=b''
        sel=selectorKey
        
        online=0
        return cls(socket, 0, request_content, sel)

    def _send_data_to_client(self, encrypted=True):
        """ Function to send the string to the client. It sends content of _send_data_to_client to the client

        """
        left_message = self._data_to_send
        self.socket.sendall(left_message)
        # left_message = left_message[bytes_sent:]

        return

    def encrypt(self, data):
        return self.sel.data["box"].encrypt(data)
    

    def _recv_data_from_client(self,size:int, encrypted=True)->int:
        """Function to recv data from client. Stores the bytes recieved in a variable named _recvd_msg.

        :param size: the size of data to receive
        :type size: int
        :param encrypted: Whether the incoming data is supposed to be encrypted, defaults to True
        :type encrypted: bool, optional
        :return: code to see if something works. Returns -1 if the connection closed
        :rtype: int
        """

        self._recvd_msg = b''
        while len(self._recvd_msg) < size:
            data = self.socket.recv(size-len(self._recvd_msg))
            if not data:
                print(f"close connection to {self.socket}")
                return -1
            self._recvd_msg += data
        if encrypted:
            self._recvd_msg = self.sel.data["box"].decrypt(self._recvd_msg)
        return 1

    def _send_msg_to_reciever(self, rcvr_sock):
        """Function to send message to a reciever
        """
        # left_message = self.sel.data["box"].encrypt(self._data_to_send)
        rcvr_sock.sendall(self._data_to_send)

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
        if self._recv_data_from_client(2, False) != 1:
            print("Connection closed")
            return -1 # Connection closed
        packed_proto_header = self._recvd_msg
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        self._recv_data_from_client(json_header_length)
        obj = self._recvd_msg
        print(obj)
        json_header = json.loads(obj.decode(ENCODING_USED))
        request = json_header["request"]
        if request == "login":
            print("request is login")
            ##!!
            self._process_login(json_header["username"], json_header["password"]) 
            return 1
        content_len = json_header['content-length']
        if content_len:
            self._recv_data_from_client(content_len)
        content_obj = self._recvd_msg
        
        
        ###################################################################
        ###################### ByteOrder Things ###########################
        ###################################################################
        content = content_obj.decode(ENCODING_USED)
        if(request == "signupuid"):
            print("request is signupuid")
            self._process_signup_uid(content)
        if(request == "signuppass"):
            print("request is signuppass")
            content = json.loads(content)
            self._process_signup_pass(content["password"], content["e2eKey"])
            return 1
        if(request == "get-key"):
            print(content)
            self._send_rcvr_key(json_header["recvr-username"]) # Get the public key of a given user
        if(request == "send-msg"):
            rcvr_uid = json_header["rcvr-uid"]
            msg_type = json_header["contexfnt-type"]
            self._send_msg(rcvr_uid, msg_type, content)
        return 1

    def _send_msg(self, rcvr_uid, msg_type, content):
        if(rcvr_uid in startServer.loggedClients.keys()):
            # We'll need to do find out the receiver's keys and box and send the message to them
            receiverSelKey = startServer.loggedClients[rcvr_uid]
            box = receiverSelKey.data["box"]
            content = box.encrypt(content)
            jsonheader = {
                "byteorder": sys.byteorder,
                "content-len": len(content),
                "sender": self.username,
                "sender_e2e_public_key": getE2EPublicKey(self.username),
                "content-type": msg_type
            }
            encoded_json_header = self._json_encode(jsonheader, ENCODING_USED)
            encoded_json_header = box.encrypt(encoded_json_header)
            proto_header = struct.pack('>H', len(encoded_json_header))
            self._data_to_send = proto_header + encoded_json_header + content
            self._send_msg_to_reciever(receiverSelKey.fileobj)
        else:
            storeMessageInDb(self.username, rcvr_uid, content)

    def _send_rcvr_key(self, rcvr_uid:str)->None:
        publickey = getE2EPublicKey(rcvr_uid)
        if publickey is None:
            # User does not exist
            # TODO
            return 0
        
        jsonheader = {
            "byteorder": sys.byteorder,
            "key": publickey
        }
        encoded_json_header = self._json_encode(jsonheader, ENCODING_USED)
        encoded_json_header = self.encrypt(encoded_json_header)
        proto_header = struct.pack('>H', len(encoded_json_header))
        self._data_to_send = proto_header + encoded_json_header
        self._send_data_to_client()

    def keyex(self)->str:
        """Does key exchange. First waits for request from the client, then sends a response with its own public key. Returns a string containing the public key of the client

        :return: public key of the client, encoded to base64
        :rtype: str
        """
        self._recv_data_from_client(2, False) 
        packed_proto_header = self._recvd_msg
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        self._recv_data_from_client(json_header_length, False)
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
            self._send_data_to_client(encrypted=False)
            return clientPublicKey
 
    def _process_login(self, username, password):
        ## Pending Imlementation
        #Required: check_login_uid returns token if uid is valid, else returns 0
        ##
        pwd_success = db_login(username, password) # Returns 1 if username and password match, else 0
        ##
        if(pwd_success == 1):
            self.status = "logged_in"
            ## online is 1 when user is logged in
            self.online = 1
            self._data_to_send = self._login_successful()
            self.sel.data["username"] = username
            self._send_data_to_client()
            # TODO: Send unread messages to user
        else:
            self._data_to_send = self._login_failed()
            self._send_data_to_client()
        
    def _login_failed(self):
        print("Login failed")
        return struct.pack('>H', 1)

    def _login_successful(self):
        print("login success")
        return struct.pack('>H', 0)

    def _successfully_found_login_uid(self, token):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "uid_found": 1,
            "logintoken": token,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        encoded_json_header = self.encrypt(encoded_json_header)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header +encoded_json_header

    def _signup_failed(self):
        print("Signup failes")
        return struct.pack('>H',2)
    
    def _successfully_signed_up(self):
        print("Signup worked")
        return struct.pack('>H',1)

    def _process_signup_uid(self,uid):
        ## Pending Implementation
        #Required: checkuid returns key, if uid is available to be used, else returns 0
        uid_free = checkIfUsernameFree(uid)
        print("Checking if UID is free")
        ##
        if not uid_free:
            print("Not free")
            self._data_to_send = self._signup_uid_not_available()
            self._send_data_to_client()
        else:
            print("Free")
            self.sel.data["username"] = uid
            self._data_to_send = self._signup_uid_available() 
            self._send_data_to_client()
            #Storing uid in socket's data
            self.username = uid
            # self.processTask() #Immediately wait for next message, which would contain the password
        return

    def _signup_uid_not_available(self):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "availability": 0,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        encoded_json_header = self.encrypt(encoded_json_header)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header +encoded_json_header
    
    def _signup_uid_available(self):
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "availability": 1,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        encoded_json_header = self.encrypt(encoded_json_header)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header + encoded_json_header
    
    def _process_signup_pass(self, password:str, e2eKey: str):
        """Process the command for signing up the user and storing the password

        :param password: The password
        :type password: str
        """
        success = createUser(self.username, password, e2eKey)
        if success:
            self._data_to_send = self._successfully_signed_up()
            self._send_data_to_client()
        else:
            self._data_to_send = self._signup_failed()
            self._send_data_to_client()

    def isOnline(self):
        if(self.online):
            return 1
        else:
            return 0

    def get_uid_selKey(self):
        return (self.username, self.sel)
