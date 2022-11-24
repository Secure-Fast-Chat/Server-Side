import json
import struct
import sys
import DatabaseRequestHandler
import selectors
from nacl.public import PrivateKey, Box
from db import checkIfUsernameFree, createUser, db_login, storeMessageInDb, getE2EPublicKey, checkIfGroupNameFree, createGroup, isGroupAdmin, addUserToGroup, getGroupMembers, getUsersGroupKey, getUnsentMessages, removeGroupMember
import datetime
import re
from typing import Tuple
# import loadbalancer
# import startServer

PROTOHEADER_LENGTH = 2 # to store length of protoheader
ENCODING_USED = "utf-8" # to store the encoding used
                        # The program uses universal encoding

class Message:
    """This is the class to handle Encryption of messages. The format in which the message is sent to client is determined in this class

    :param socket: The socket used for connection with Server
    :type socket: socket.socket
    :param request_content: Content to include in the request to send to server
    :type request_content: dict
    :param _data_to_send: Contains the data to send to the server
    :type _data_to_send: bytes
    :param _recvd_msg: Content received from server is stored here
    :type _recvd_msg: bytes
    """

    def __init__(self,conn_socket,status,request,sel, loggedClients, lbsock, encrypt=True):
        """Constructor Object

        :param conn_socket: Socket which has a connection with client
        :type conn_socket: socket.socket
        :param request: Content to send to server
        :type request: str
        :param encrypt: Whether the received data would be encrypted
        :type exncrypt: bool, Optional, defaults to True
        """
        self.status = status
        self.socket = conn_socket
        self.request_content = request
        self._data_to_send = b''
        self.sel = sel
        self.logged_clients = loggedClients
        self.username = ""
        try:
            # breakpoint()
            self.username = sel.data["username"] # Need this to keep track of whom we are signing up etc
        except:
            self.username = ""
        self.online = self.username != "" and self.username in self.logged_clients.keys()
        
        self.lbsock = lbsock
        self.is_encrypted = encrypt
        self.newLogin = False

    @classmethod 
    def fromSelKey(cls, selectorKey, loggedClients, lbsock, encrypt=True):
        """Custom constructor to initialise a message given just the selector key

        :param selectorKey: the selector key containitnall the data
        :type selectorKey: SelectorKey
        :return: Message
        :rtype: Message
        """
        socket = selectorKey.fileobj
        request_content=""
        sel=selectorKey
        
        return cls(socket, 0, request_content, sel, loggedClients, lbsock, encrypt)

    def _send_data_to_client(self):
        """Function to send the string to the client. It sends content of _send_data_to_client to the client.
        """
        # Note that this does not do any encryption, do any encryption before sending into this
        left_message = self._data_to_send
        self.socket.sendall(left_message)
        return

    def encrypt(self, data: bytes)->bytes:
        """_summary_

        :param data: the data to encrypt
        :type data: bytes
        :return: Encrypted Message
        :rtype: bytes
        """
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

        if size == 0:
            return
        self._recvd_msg = b''
        while len(self._recvd_msg) < size:
            # print("hi,can you find bug")
            try:
                data = self.socket.recv(size-len(self._recvd_msg))
            except BlockingIOError:
                return -1
            if not data:
                print(f"close connection to {self.socket}")
                return -1
            self._recvd_msg += data
        # print('hey there ',encrypted,self._recvd_msg)
        if encrypted and self.is_encrypted:
            self._recvd_msg = self.sel.data["box"].decrypt(self._recvd_msg)
        # print('ho',self._recvd_msg)
        return 1

    def _send_msg_to_reciever(self, rcvr_sock):
        """Function to send message to a reciever

        :param rcvr_sock: The socket to which to send
        :type rcvr_sock: Socket
        """
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

        print("ME IS CALLED NOWNOW NOW")
        if self._recv_data_from_client(2, False) != 1 or self._recvd_msg == b'':
            # print("Connection closed")
            return -1 # Connection closed
        packed_proto_header = self._recvd_msg
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        self._recv_data_from_client(json_header_length)
        obj = self._recvd_msg
        # print(obj)
        json_header = json.loads(obj.decode(ENCODING_USED))
        request = json_header["request"]
        if request == "login":
            # print("request is login")
            self._process_login(json_header["username"], json_header["password"])
            return 1
        content_len = json_header['content-length']
        if content_len:
            if request == 'send-msg':
                self._recv_data_from_client(content_len,encrypted=False)
            else:
                self._recv_data_from_client(content_len)
        content_obj = self._recvd_msg
        
        
        ###################################################################
        ###################### ByteOrder Things ###########################
        ###################################################################
        if(request == "send-msg" or request == "send-group-message" or request == "pls-relay"):
            content = content_obj
        else:
            content = content_obj.decode(ENCODING_USED)
        if(request == "signupuid"):
            # print("request is signupuid")
            self._process_signup_uid(content)
        if request == "pls-relay":
            print("Relaying")
            receiver = json_header["receiver"]
            msg_type = json_header["content-type"]
            if "guid" in json_header.keys():
                grp_uid = json_header["guid"]
            else:
                grp_uid = None
            sender  =json_header["sender"]
            timestamp  =json_header["timestamp"]
            self._send_msg(receiver, msg_type, content, grp_uid, sender, timestamp, True)
        if(request == "signuppass"):
            # print("request is signuppass")
            content = json.loads(content)
            self._process_signup_pass(content["password"], content["e2eKey"])
            return 1
        if not self.online:
            return 1
        if(request == "get-key"):
            print(content)
            self._send_rcvr_key(json_header["recvr-username"]) # Get the public key of a given user
        if(request == "send-msg"):
            rcvr_uid = json_header["rcvr-uid"]
            msg_type = json_header["content-type"]
            self._send_msg(rcvr_uid, msg_type, content)
        if(request == "create-grp"):
            grp_uid = json_header["guid"]
            grp_key = json_header["group-key"]
            self._create_grp(grp_uid, grp_key)
        if(request == "add-mem"):
            grp_uid = json_header["guid"]
            new_uid = json_header["new-uid"]
            user_grp_key = json_header["user-grp-key"]
            self._add_grp_mem(grp_uid, new_uid, user_grp_key)
        if(request == "remove-mem"):
            grp_uid = json_header["guid"]
            uid = json_header["uid"]
            self._rem_grp_mem(grp_uid, uid)
        if(request == 'send-group-message'):
            grp_uid = json_header["guid"]
            msg_type = json_header["content-type"]
            self._send_grp_message(grp_uid, msg_type, content)
        if request == "grp-key":
            self._send_group_key(json_header["group-name"], self.username)
        if request == 'leave-grp':
            self._handle_leave_group_request(json_header['guid'],self.username)
        

        # print("Unknown request")
        print(request)
        return 1

    def _handle_leave_group_request(self,grp_uid,uid):
        """ Function to remove member from group based on leave request

        :param guid: Group to remove from
        :type guid: str
        :param uid: user to remove
        :type uid: str
        """

        response = 0
        grp_uid_exists = not checkIfGroupNameFree(grp_uid)
        if(not grp_uid_exists):
            response = 1 # Group does not exist
        else:
            userList = getGroupMembers(grp_uid)
            if(uid not in userList):
                response = 1
            else:
                removeGroupMember(grp_uid, uid)
                response = 0
        self._data_to_send = struct.pack('>H',response)
        self._send_data_to_client()

    def _rem_grp_mem(self, grp_uid, uid):
        response = 0
        grp_uid_exists = not checkIfGroupNameFree(grp_uid)
        if(not grp_uid_exists):
            response = 1 # Group does not exist
        else:
            userList = getGroupMembers(grp_uid)
            valid_admin = isGroupAdmin(grp_uid, self.username) # True if admin
            if not valid_admin:
                response = 2
            elif(uid not in userList):
                response = 3
            else:
                removeGroupMember(grp_uid, uid)
                response = 0
        self._data_to_send = struct.pack('>H',response)
        self._send_data_to_client()

    def _send_grp_message(self, grp_uid, msg_type, content):
        """Send messages in a group

        :param grp_uid: Id of the group in which message is to be sent
        :type grp_uid: str
        :param msg_type: Type of message to be send, text or file object
        :type msg_type: str
        :param content: message to be sent
        :type content: str
        """
        response = 0
        grp_uid_exists = not checkIfGroupNameFree(grp_uid)
        if(not grp_uid_exists):
            response = 2 # Group does not exist
        else:
            grp_members = getGroupMembers(grp_uid)
            if(self.username not in grp_members):
                response = 1
            for member in grp_members:
                if(member == self.username):
                     continue
                self._send_msg(member, msg_type, content, grp_uid = grp_uid)
        self._data_to_send = struct.pack('>H',response)
        self._send_data_to_client()
            
    def _add_grp_mem(self, grp_uid, new_uid, user_grp_key):
        """Function to add a new member in the group

        :param grp_uid: id of the group in which member is to be added
        :type grp_uid: str
        :param new_uid: user id of the new user which is to be added in the group
        :type new_uid: str
        :param user_grp_key: Public key of the group
        :type user_grp_key: str"""
        
        grpNameFree = checkIfGroupNameFree(grp_uid)
        user_exists = not checkIfUsernameFree(new_uid)
        response = 1
        if grpNameFree:
            response = 1
        else:
            valid_admin = isGroupAdmin(grp_uid, self.username) # True if admin
            if not valid_admin:
                response = 2
            elif not user_exists:
                response = 3
            elif new_uid in getGroupMembers(grp_uid):
                response = 4
            else:
                addUserToGroup(grp_uid, new_uid, user_grp_key)
                response = 0
        self._data_to_send = struct.pack('>H',response)
        self._send_data_to_client()

    def _create_grp(self, grp_uid:str, grp_key:str):
        """Creates a new group

        :param grp_uid: name of the group
        :type grp_uid: str
        :param grp_key: the key used for encrypting messages
        :type grp_key: str
        :return: 1 if there was an error, 0 otherwise
        :rtype: int
        """
        grpNameFree = checkIfGroupNameFree(grp_uid)
        response = 1
        if not grpNameFree:
            response = 1
        else:
            grp_created = createGroup(grp_uid, grp_key, self.username, getE2EPublicKey(self.username)) #True if group created successfully

            if grp_created:
                response = 0
            else:
                response = 1

        self._data_to_send = struct.pack('>H',response)
        self._send_data_to_client()

    def _send_group_key(self, grp_name:str, username:str)->None:
        """Sends a json response containing the group key for a particular user, which can be decrypted by only that user to get the actual private key

        :param grp_name: name of the group
        :type grp_name: str
        :param username: name of the user
        :type username: str
        """
        grpKey, creatorPubKey = getUsersGroupKey(grp_name, username) 
        jsonheader ={
                "byteorder": sys.byteorder,
                'group-key': grpKey,
                'creatorPubKey' : creatorPubKey,
            } 
        encoded_json_header = self._json_encode(jsonheader, ENCODING_USED)
        encoded_json_header = self.encrypt(encoded_json_header)
        proto_header = struct.pack('>H', len(encoded_json_header))

        self._data_to_send = proto_header + encoded_json_header
        self._send_data_to_client()

    def _send_msg(self, rcvr_uid, msg_type, content, grp_uid = None, sender = None, timestamp = None, save=False):
        """Sends messages to the specified user

        :param rcvr_uid: User ID of the reciever client
        :type rcvr_uid: str
        :param msg_type: Type of message, text or file 
        :type msg_type: str
        :param content: Encrypted message to be sent
        :type content: str
        :param grp_uid: GroupId in case of group message
        :type grp_uid: str
        :param sender: name of the message sender, in case of group chat, it is grp_id::user_id, otherwise it is username of self
        :type sender: str
        :param save: whether to save if the receiver is not directly connected to the server
        :type save: bool
        """
        print("I am message")
        if(sender is None):
            if not grp_uid:
                sender = self.username
            else:
                sender = grp_uid + "::" + self.username
        if not timestamp:
            timestamp = datetime.datetime.timestamp(datetime.datetime.now())
        sent = False
        if(rcvr_uid in self.logged_clients.keys()):
            # We'll need to do find out the receiver's keys and box and send the message to them
            receiverSelKey = self.logged_clients[rcvr_uid]
            box = receiverSelKey.data["box"]
            # breakpoint()
            content = box.encrypt(content)
            jsonheader = {
                "byteorder": sys.byteorder,
                "content-length": len(content),
                "sender": sender,
                "sender_e2e_public_key": getE2EPublicKey(sender),
                "content-type": msg_type,
                "timestamp": timestamp,
                'sender-type': 'user',
            }
            if grp_uid:
                jsonheader['sender_e2e_public_key'] = getE2EPublicKey(sender.split("::")[1])
                jsonheader['sender-type'] = 'group'
                jsonheader['group-key'], jsonheader['creatorPubKey'] = getUsersGroupKey(grp_uid, rcvr_uid)
                
            # print(f"Sending messages {jsonheader}")
            encoded_json_header = self._json_encode(jsonheader, ENCODING_USED)
            encoded_json_header = box.encrypt(encoded_json_header)
            proto_header = struct.pack('>H', len(encoded_json_header))
            self._data_to_send = proto_header + encoded_json_header + content
            self._send_msg_to_reciever(receiverSelKey.fileobj)
            sent = True
            ##!!
            # response = struct.unpack('>H',self._recv_data_from_client(2))[0]
            # if response == 0:
            #     sent = True
            ##!!
        if not sent:
            if save:
                print("Storing message")
                # breakpoint()
                storeMessageInDb(sender, rcvr_uid, content, timestamp, msg_type)
                print("Storing to db")
            else:
                # send this data to load balancer
                jsonheader = {
                    "byteorder": sys.byteorder,
                    "request": "pls-relay",
                    "content-length": len(content),
                    "sender": sender,
                    "receiver": rcvr_uid,
                    "content-type": msg_type,
                    "timestamp": timestamp,
                    'sender-type': 'user',
                }
                if grp_uid:
                    jsonheader['sender-type'] = 'group'
                    jsonheader["guid"] = grp_uid
                encoded_json_header = self._json_encode(jsonheader, ENCODING_USED)
                proto_header = struct.pack('>H', len(encoded_json_header))
                self._data_to_send = proto_header + encoded_json_header + content
                self._send_msg_to_reciever(self.lbsock)

    def _send_rcvr_key(self, rcvr_uid:str)->None:
        """Gets the public key of a given user

        :param rcvr_uid: User id of the user whose public key is requested
        :type rcvr_uid: str
        """
        publickey = getE2EPublicKey(rcvr_uid)
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
        if self._recv_data_from_client(2, False) != 1:
            return -1
        packed_proto_header = self._recvd_msg
        json_header_length = struct.unpack('>H', packed_proto_header)[0]
        self._recv_data_from_client(json_header_length, False)
        obj = self._recvd_msg
        json_header = json.loads(obj.decode(ENCODING_USED))
        if 'request' not in json_header.keys():
            #### PENDING ####
            pass
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
        self._send_data_to_client()
        return clientPublicKey
 
    def _process_login(self, username, password):
        """Processes Login Request
        On successful login sends pending messages

        :param username: Username of the Client to be logged in 
        :type username: str
        :param password: Password of the Client to be logged in
        :type password: str 
        """
        valid_uid = self.checkValidityOfUID(username)
        if not valid_uid:
            self._data_to_send = struct.pack('>H',3)
            self._send_data_to_client()
        else:
            pwd_success = db_login(username, password) # Returns 1 if username and password match, else 0
            if(pwd_success == 1):
                self.status = "logged_in"
                ## online is 1 when user is logged in
                self.online = 1
                self._data_to_send = self._login_successful()
                self.sel.data["username"] = username
                self.username = username
                self._send_data_to_client()
                self.newLogin = True                    
                self.logged_clients[self.username] = self.sel
                # self._send_successful_login_info_to_lb()
                # (SENDER, RECEIVER, MESSAGE, TIMESTAMP, CONTENTTYPE)
                unsent_messages = getUnsentMessages(self.username)
                count = 0
                for msg in unsent_messages:
                    (sender, rcvr, messg, timestamp, msgtype) = msg
                    messg = messg.encode(ENCODING_USED)
                    guid = None
                    if("::" in sender):
                        guid = sender[0:sender.find("::")]
                    self._send_msg(rcvr, msgtype, messg, grp_uid = guid, sender = sender,timestamp = timestamp)

            else:
                self._data_to_send = self._login_failed()
                self._send_data_to_client()
        
    def _login_failed(self)->bytes:
        """Returns the response to send after a failed login attempt

        :return: reponse after failed login
        :rtype: bytes
        """
        print("Login failed")
        return struct.pack('>H', 1)

    def _login_successful(self)->bytes:
        """Returns the response after a succesful login

        :return: response after a succesful login
        :rtype: bytes
        """
        print("login success")
        return struct.pack('>H', 0)

    def _signup_failed(self)->bytes:
        """Returns the response to send after a failed signup attempt

        :return: reponse after failed signup
        :rtype: bytes
        """ 
        print("Signup failed")
        return struct.pack('>H',2)
    
    def _successfully_signed_up(self)->bytes:
        """Returns the response to send after a succesful login attempt

        :return: reponse after succesful login
        :rtype: bytes
        """
        print("Signup worked")
        return struct.pack('>H',1)

    def _process_signup_uid(self,uid:str)->None:
        """Processes Signup Request by validating if requested Uid already exists or not

        :param uid: User ID of new user
        :type uid: str
        """

        valid_uid = self.checkValidityOfUID(uid)
        if not valid_uid:
            self._data_to_send = self._invalid_uid_type()
            self._send_data_to_client()
        else:
            uid_free = checkIfUsernameFree(uid)
            print("Checking if UID is free")
            ##
            if not uid_free:
                self._data_to_send = self._signup_uid_not_available()
                self._send_data_to_client()
            else:
                self.sel.data["username"] = uid
                self._data_to_send = self._signup_uid_available() 
                self._send_data_to_client()
                #Storing uid in socket's data
                self.username = uid
        return

    def _invalid_uid_type(self):
        """Returns the response to send if the username is of the wrong type

        :return: protoheader + a json header which does not containt the availability key
        :rtype: bytes
        """
        global ENCODING_USED
        jsonheader = {
            "byteorder": sys.byteorder,
            "content-length": 0
        }
        encoded_json_header = self._json_encode(jsonheader,ENCODING_USED)
        encoded_json_header = self.encrypt(encoded_json_header)
        proto_header = struct.pack('>H',len(encoded_json_header))
        return proto_header +encoded_json_header

    def checkValidityOfUID(self, uid):
        """ Function to check if the uid is valid. A valid uid is one which has only a-z,A-Z,0-9,_ characters

        :param uid: User id to check for
        :type uid: str
        :return: Return True if valid
        :rtype: bool
        """

        pattern = re.compile(r'[a-zA-Z0-9_]+')
        if not re.fullmatch(pattern,uid):
            return False
        return True

    def _signup_uid_not_available(self)->bytes:
        """Returns the response to send if the username is already taken

        :return: protoheader + a json header saying that the availability is 0 
        :rtype: bytes
        """
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
    
    def _signup_uid_available(self)->bytes:
        """Returns the response to send if the username is free

        :return: protoheader + a json header saying that the availability is 1
        :rtype: bytes
        """
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
    
    def _process_signup_pass(self, password:str, e2eKey: str)->None:
        """Process the command for signing up the user and storing the password

        :param password: The password
        :type password: str
        """
        if self.username == "":
            self._data_to_send = self._signup_failed()
            self._send_data_to_client()
 
        success = createUser(self.username, password, e2eKey)
        if success:
            self._data_to_send = self._successfully_signed_up()
            self._send_data_to_client()
        else:
            self._data_to_send = self._signup_failed()
            self._send_data_to_client()

    def isOnline(self)->bool:
        """Returns if the user is online

        :return: Is the user online
        :rtype: bool
        """
        if self.online:
            return True
        else:
            return False

    def get_uid_selKey(self)-> Tuple[str, selectors.SelectorKey, bool]:
        """Helper function to get the username and selectorkey

        :return: A tuples containing the username and selectorkey and whether this message led to a new login
        :rtype: tuple[str, selectors.SelectorKey, bool]
        """
        return (self.username, self.sel, self.newLogin)
