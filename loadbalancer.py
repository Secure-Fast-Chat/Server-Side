import lb_msg
import selectors
import socket
from nacl.public import PrivateKey, Box
from startServer import startServer
from nacl.public import PrivateKey
from typing import Tuple
import random
import json
import struct


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


serverAddrs = [
    ("127.0.0.1", 8001),
    ("127.0.0.1", 8002),
    ("127.0.0.1", 8003),
    ("127.0.0.1", 8004),
    ("127.0.0.1", 8005),
]



global serverSockets
serverSockets = {}

def getFreeServer()->int:
    return random.randint()%5

def registerServer(addr: Tuple[str, int]):
    global sel
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(addr)
    sock.setblocking(False)
    events = selectors.EVENT_READ
    sel.register(sock, events, data={addr})
    global serverSockets
    serverSockets[addr] = sock


def sendHostDataToClient(sel, sock):
    serverAddress = serverAddrs[getFreeServer]
    header = {
        'host': serverAddress[0],
        'port': serverAddress[1],
    }
    header = json.dumps(header, ensure_ascii=False).encode("utf-8") #Don't need to send using a particular encoding, this will just be a string and int
    protoheader = struct.pack(">H", len(header))
    sock.sendall(protoheader + header)

    
        
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
                    relayMessage(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
