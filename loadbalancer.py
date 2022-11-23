#make a listening socket
import selectors
import socket
from startServer import startServer
from nacl.public import PrivateKey
serverAddrs = [
    ("127.0.0.1", 8001),
    ("127.0.0.1", 8002),
    ("127.0.0.1", 8003),
    ("127.0.0.1", 8004),
    ("127.0.0.1", 8005),
]

LBHOST = "127.0.0.1"
LBPORT = 8000



if __name__ == "__main__":
    global sel
    sel = selectors.DefaultSelector()
    serverSockets = []
    privateKey = PrivateKey.generate()
    for i in serverAddrs:
        startServer(privateKey,i[0], i[1])

    Message.LOGGED_CLIENTS = {}
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(LBHOST,LBPORT)
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
