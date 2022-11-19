import Message
import selectors
import getpass
import socket
import types
import struct
import json
from nacl.public import PrivateKey, Box
import nacl
from nacl.encoding import Base64Encoder
HOST = "127.0.0.1"
PORT = 8000
ENCODING_USED = "utf-8"





def accept(sel, sock):
    """Function to accept a new client connection
    """
    print(f"{sock=}")
    conn, addr = sock.accept()
    print(f"Connected by {addr}")
    
    privatekey = PrivateKey.generate()
    publickey = privatekey.public_key
    message = Message.Message(conn, 'keyex', {"key": publickey.encode(Base64Encoder).decode()}, sel)

    clientPublicKey = nacl.public.PublicKey(message.keyex(), encoder=Base64Encoder)
    print(f"Keys Exchanged. client public key = {clientPublicKey}")
    print(f"My public key is {publickey}")
    events = selectors.EVENT_READ
    box = Box(privatekey, clientPublicKey)
    conn.setblocking(False)
    sel.register(conn, events, data={"box":box})
    ##!!
    print("Accepted Client")
    ##!!

def service(key, mask):
    ##!!
    print("Processing request")
    ##!!
    sock = key.fileobj
    message =  Message.Message.fromSelKey(key)
    global loggedClients
    global sel
    if message.processTask() != -1:
        uid, selKey = message.get_uid_selKey()

        loggedClients[uid] = selKey
    else:
        uid, selKey = message.get_uid_selKey()
        sock = selKey.fileobj
        sel.unregister(sock)
        sock.close()
        if(uid!=""):
            del loggedClients[uid]




if __name__ == "__main__":
    global sel
    sel = selectors.DefaultSelector()
    global loggedClients
    loggedClients = {}
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((HOST,PORT))
    lsock.listen()
    lsock.setblocking(False)
    
    sel.register(lsock, selectors.EVENT_READ, data = None)
    try:
        while True:
            print("Reached//")
            events = sel.select(timeout = None)
            print(events)
            for key, mask in events:
                if key.data is None:
                    accept(sel, key.fileobj)
                else:
                    service(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()