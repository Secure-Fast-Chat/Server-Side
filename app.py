import Message
import selectors
import getpass
import socket
import types
import struct
import json

HOST = "127.0.0.1"
PORT = 6969
ENCODING_USED = "utf-8"

loggedClients = []




def accept(sock = None):
    """Function to accept a new client connection
    """
    conn, addr = sock.accept()
    conn.setblocking(False)
    message = Message.Message(conn, 'new-client', {})
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=message)


def service(key, mask):
    sock = key.fileobj
    message =  key.data
    packed_proto_header = sock.recv(2)
    json_header_length = struct.unpack('>H', packed_proto_header)[0]
    obj = sock.recv(json_header_length)
    json_header = json.loads(obj.decode(ENCODING_USED))
    content_len = json_header['content-length']
    content_obj = sock.recv(content_len)
    content = json.loads(content_obj.decode(ENCODING_USED))
    if(json_header["request"]=='signupuid'):
        uid = content
        if(_check_valid_uid(uid)):
            

def _check_valid_uid(uid):
    """Sends Uid to database and checks if it is valid or not

    :return: 1 if valid, 0 if invalid
    :rtype: int
    """
    pass




if __name__ == "main":
    sel = selectors.DefaultSelector()
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_sock.bind((HOST,PORT))
    s_sock.listen()
    s_sock.setblocking(False)
    sel.register(s_sock, selectors.EVENT_READ, data = None)
    try:
        while True:
            events = sel.select(timeout = None)
            for key, mask in events:
                if key.data is None:
                    accept(key.fileobj)
                else:
                    service(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()