import lb_msg
import selectors
import socket
from nacl.public import PrivateKey, Box
from startServer import startServer
from nacl.public import PrivateKey
from typing import Tuple
import random

ENCODING_USED = "utf-8"
LBHOST = "127.0.0.1"
LBPORT = 8000

def accept(sel, sock):
    """Function to accept a new client connection
    """

    print(f"{sock}")
    conn, addr = sock.accept()
    print(f"Connected by {addr}")
    
    lb_msg.NameItYourself(conn).processClient()

    sock.close()
    print("Connection Closed")
#make a listening socket


serverAddrs = lb_msg.SERVER_MAPPING

global serverSockets
serverSockets = {}


def registerServer(addr: Tuple[str, int]):
    global sel
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(addr)
    sock.setblocking(False)
    events = selectors.EVENT_READ
    sel.register(sock, events, data={addr})
    global serverSockets
    serverSockets[addr] = sock

        
if __name__ == "__main__":
    global sel
    sel = selectors.DefaultSelector()

    serverSockets = []
    privateKey = PrivateKey.generate()
    for i in serverAddrs:
        startServer(privateKey,i[0], i[1])
        registerServer(i)

    lb_msg.LOGGED_CLIENTS = {}
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(LBHOST,LBPORT)
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
                    pass
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
