import lb_msg
import selectors
import socket
import types
import struct
import json
from nacl.public import PrivateKey, Box
import nacl
from nacl.encoding import Base64Encoder
HOST = "127.0.0.1"
PORT = 8080
ENCODING_USED = "utf-8"

def accept(sel, sock):
    """Function to accept a new client connection
    """

    print(f"{sock}")
    conn, addr = sock.accept()
    print(f"Connected by {addr}")
    
    lb_msg.NameItYourself(conn).processClient()

    sel.unregister(sock)
    sock.close()
    print("Connection Closed")



if __name__ == "__main__":
    global sel
    sel = selectors.DefaultSelector()
    lb_msg.LOGGED_CLIENTS = {}
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((HOST,PORT))
    lsock.listen()
    lsock.setblocking(False)
    
    sel.register(lsock, selectors.EVENT_READ, data = None)
    try:
        while True:
            events = sel.select(timeout = None)
            for key, mask in events:
                if key.data is None:
                    # New client tried to connect
                    accept(sel, key.fileobj)
                else:
                    # Server is sending a message
                    # relayMessage(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
