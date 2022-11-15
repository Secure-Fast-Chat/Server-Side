import Message
import selectors
import getpass
import socket
import types
import struct
import json

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
    message = Message.Message(conn, 'new-client', {}, sel)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=message)
    ##!!
    print("Accepted Client")
    ##!!

def service(key, mask):
    ##!!
    print("Processing request")
    ##!!
    sock = key.fileobj
    message =  key.data
    message.processTask()
            

def check_valid_uid(uid):
    """Sends Uid to database and checks if it is valid or not

    :return: 1 if valid, 0 if invalid
    :rtype: int
    """
    pass




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