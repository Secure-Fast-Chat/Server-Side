import Message
import selectors
import getpass
import socket
import types
import struct
import json
from nacl.public import PrivateKey, Box

HOST = "127.0.0.1"
PORT = 8000
ENCODING_USED = "utf-8"

loggedClients = []



def accept(sel, sock = None):
    """Function to accept a new client connection
    """
    print(sock)
    conn, addr = sock.accept()
    conn.setblocking(False)
    privatekey = PrivateKey.generate()
    publickey = privatekey.public_key
    message = Message.Message(conn, 'keyex', {"key": publickey}, sel)
    clientPublicKey = message.keyex()

    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    box = Box(privatekey, clientPublicKey)
    sel.register(conn, events, data={"box":box})
    ##!!
    print("Accepted Client")
    ##!!

def service(key, mask):
    ##!!
    print("Processing request")
    ##!!
    sock = key.fileobj
    # message =  key.data
    # message.processTask()
            





if __name__ == "__main__":
    sel = selectors.DefaultSelector()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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