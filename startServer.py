import Message
import selectors
import socket
from nacl.public import PrivateKey, Box
import nacl
from nacl.encoding import Base64Encoder
import sys
import struct
import json

ENCODING_USED = "utf-8"

LBSOCK = None
def accept(sel, sock):
    """Function to accept a new client connection
    """
    # print(f"{sock=}")
    conn, addr = sock.accept()
    # print(f"Connected by {addr}")
    conn.setblocking(False)
    events = selectors.EVENT_READ
    sel.register(conn, events, data={"notDoneKeyEx":True})


def doKeyex(sel, conn):
    global privatekey
    
    publickey = privatekey.public_key
    message = Message.Message(conn, 'keyex', {"key": publickey.encode(Base64Encoder).decode()}, sel, LOGGED_CLIENTS, LBSOCK)


    key = message.keyex()
    if key == -1:
        # print("closing keyex")
        # sel.unregister(sock)
        conn.close()
        return

    clientPublicKey = nacl.public.PublicKey(key, encoder=Base64Encoder)
    # print(f"Keys Exchanged. client public key = {clientPublicKey}")
    # print(f"My public key is {publickey}")
    
    box = Box(privatekey, clientPublicKey)
    sel.unregister(conn)
    events = selectors.EVENT_READ
    sel.register(conn, events, data={"box":box})

    ##!!
    print("Accepted Client")
    ##!!

def service(key, mask, HOST, PORT):
    global LOGGED_CLIENTS
    sock = key.fileobj
    if  "loadbalancer" in key.data.keys():
        # breakpoint()
        message =  Message.Message.fromSelKey(key, LOGGED_CLIENTS, LBSOCK, False)
        message.processTask()
        return
    
    global sel
    if "notDoneKeyEx" in key.data.keys():
        doKeyex(sel, key.fileobj)
        return
    # breakpoint()
    message =  Message.Message.fromSelKey(key, LOGGED_CLIENTS, LBSOCK)
    if message.processTask() != -1:
        uid, selKey, newLogin = message.get_uid_selKey()
        if uid != "":
            # print(LOGGED_CLIENTS)
            if newLogin:
                send_lb_new_login_info(uid, HOST, PORT)
                # Only send if we didnt have the user connected already
            LOGGED_CLIENTS[uid] = selKey
            
    else:
        uid, selKey, newLogin = message.get_uid_selKey()
        sock = selKey.fileobj
        sel.unregister(sock)
        sock.close()
        if(uid!=""):
            del LOGGED_CLIENTS[uid]
            send_lb_logout_info(uid)

def send_lb_logout_info(uid):
    json_header = {
        "byteorder": sys.byteorder,
        "request": "user-logout",
        "uid": uid,
        "content-length": 0,
    }
    json_header = json.dumps(json_header, ensure_ascii=False).encode(ENCODING_USED)
    LBSOCK.sendall(struct.pack('>H', len(json_header)) + json_header)

def send_lb_new_login_info(uid, HOST, PORT):
    json_header = {
        "byteorder": sys.byteorder,
        "request": "new-login",
        "content-length": 0,
        "uid": uid,
        "host": HOST,
        "port": PORT
    }
    json_header = json.dumps(json_header, ensure_ascii=False).encode(ENCODING_USED)
    LBSOCK.sendall(struct.pack('>H', len(json_header)) + json_header)

def startServer(pvtKey, HOST = "127.0.0.1", PORT = 8000):
    global privatekey
    privatekey = pvtKey
    global sel
    sel = selectors.DefaultSelector()
    global LOGGED_CLIENTS
    LOGGED_CLIENTS = {}
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((HOST,PORT))
    lsock.listen()
    global LBSOCK
    LBSOCK, lbaddr = lsock.accept() # The first connection would be load balancer
    sel.register(LBSOCK, selectors.EVENT_READ, data = {"loadbalancer": lbaddr})
    # print(f"The socket is at {LBSOCK}")
    lsock.listen()

    lsock.setblocking(False)

    
    sel.register(lsock, selectors.EVENT_READ, data = None)
    try:
        while True:
            # print("Reached//")
            events = sel.select(timeout = None)
            for key, mask in events:
                # print(key.data)
                if key.data is None:
                    accept(sel, key.fileobj)
                else:
                    service(key, mask, HOST, PORT)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()

if __name__ == "__main__":
    startServer(PrivateKey.generate(), sys.argv[1], int(sys.argv[2]))
