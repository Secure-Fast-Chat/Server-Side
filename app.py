import Message
import selectors
import getpass
import socket
import types
import struct
import json

HOST = "127.0.0.1"
PORT = 6969
ENCODING_USED = "utf-8"

loggedClients = []




def accept(sock = None):
    """Function to accept a new client connection
    """
    conn, addr = sock.accept()
    conn.setblocking(False)
    message = Message.Message(conn, 'new-client', {})
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=message)


def service(key, mask):
    sock = key.fileobj
    message =  key.data
    message.process()
            

def check_valid_uid(uid):
    """Sends Uid to database and checks if it is valid or not

    :return: 1 if valid, 0 if invalid
    :rtype: int
    """
    pass




if __name__ == "main":
    sel = selectors.DefaultSelector()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((HOST,PORT))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data = None)
    try:
        while True:
            events = sel.select(timeout = None)
            for key, mask in events:
                if key.data is None:
                    accept(key.fileobj)
                else:
                    service(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()