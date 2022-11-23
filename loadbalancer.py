import lb_msg
import selectors
import socket
from nacl.public import PrivateKey, Box
from startServer import startServer
from nacl.public import PrivateKey


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

    sel.unregister(sock)
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





if __name__ == "__main__":
    global sel
    sel = selectors.DefaultSelector()

    serverSockets = []
    privateKey = PrivateKey.generate()
    for i in serverAddrs:
        startServer(privateKey,i[0], i[1])

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
                print('going good ')
                if key.data is None:
                    # New client tried to connect
                    accept(sel, key.fileobj)
                else:
                    service(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
