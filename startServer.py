import Message
import selectors
import socket
from nacl.public import PrivateKey, Box
import nacl
from nacl.encoding import Base64Encoder
import sys
ENCODING_USED = "utf-8"
LOGGED_CLIENTS = {}
LBSOCK = None
def accept(sel, sock):
    """Function to accept a new client connection
    """
    print(f"{sock=}")
    conn, addr = sock.accept()
    print(f"Connected by {addr}")
    global privatekey
    
    publickey = privatekey.public_key
    message = Message.Message(conn, 'keyex', {"key": publickey.encode(Base64Encoder).decode()}, sel, LOGGED_CLIENTS, LBSOCK)

    key = message.keyex()
    if key == -1:
        print("closing keyex")
        # sel.unregister(sock)
        conn.close()
        return

    clientPublicKey = nacl.public.PublicKey(key, encoder=Base64Encoder)
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
    # breakpoint()
    message =  Message.Message.fromSelKey(key, LOGGED_CLIENTS, LBSOCK)
    global sel
    if message.processTask() != -1:
        pass
        uid, selKey = message.get_uid_selKey()
        if uid != "":
            LOGGED_CLIENTS[uid] = selKey
    else:
        uid, selKey = message.get_uid_selKey()
        sock = selKey.fileobj
        sel.unregister(sock)
        sock.close()
        if(uid!=""):
            del LOGGED_CLIENTS[uid]

def startServer(pvtKey, HOST = "127.0.0.1", PORT = 8000):
    global privatekey
    privatekey = pvtKey
    global sel
    sel = selectors.DefaultSelector()
    LOGGED_CLIENTS = {}
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((HOST,PORT))
    lsock.listen()

    LBSOCK, lbaddr = lsock.accept() # The first connection would be load balancer
    lsock.listen()

    lsock.setblocking(False)

    
    sel.register(lsock, selectors.EVENT_READ, data = None)
    try:
        while True:
            print("Reached//")
            events = sel.select(timeout = None)
            for key, mask in events:
                print('going good ')
                if key.data is None:
                    accept(sel, key.fileobj)
                else:
                    service(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()

if __name__ == "__main__":
    startServer(PrivateKey.generate(), sys.argv[1], int(sys.argv[2]))