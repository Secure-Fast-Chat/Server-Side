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
LBSOCK_SELECTOR = None
def accept(sel, sock):
    """Function to accept a new client connection
    """
    # print(f"{sock=}")
    conn, addr = sock.accept()
    # print(f"Connected by {addr}")
    conn.setblocking(False)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data={"notDoneKeyEx":True})


def doKeyex(conn, selkey):
    global sel
    global privatekey

    publickey = privatekey.public_key
    message = Message.Message(conn, 'keyex', {"key": publickey.encode(Base64Encoder).decode()}, selkey, LOGGED_CLIENTS, LBSOCK, sel)


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
    newdata = selkey.data
    newdata["box"] = box
    sel.unregister(conn)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=newdata)

    ##!!
    print("Accepted Client")
    ##!!

def service(key, mask, HOST, PORT):
    if mask & selectors.EVENT_READ:
        global sel
        global LOGGED_CLIENTS
        sock = key.fileobj
        print(f"New read {key}")
        if  "loadbalancer" in key.data.keys():
            breakpoint()
            if (not "left" in key.data.keys()) or key.data["left"] == 0:
                message =  Message.Message.fromSelKey(key, LOGGED_CLIENTS, LBSOCK, sel,False)
            else:
                message = key.data["message"]
            message.processTask()
            return
        
        if "notDoneKeyEx" in key.data.keys() and key.data["notDoneKeyEx"] == True:
            
            doKeyex(key.fileobj, key)
            del key.data["notDoneKeyEx"]
            return
        # breakpoint()
        if (not "left" in key.data.keys()) or key.data["left"] == 0:
            message =  Message.Message.fromSelKey(key, LOGGED_CLIENTS, LBSOCK, sel)
        else:
            message = key.data["message"]
        if message.processTask() != -1:
            uid, selKey, newLogin = message.get_uid_selKey()
            if uid != "":
                print(len(LOGGED_CLIENTS.keys()))
                if newLogin:
                    content = send_lb_new_login_info(uid, HOST, PORT)
                    key_lb = sel.get_key(LBSOCK)
                    if 'to_send' not in key_lb.data.keys():
                        key_lb.data['to_send'] = b''
                    key_lb.data['to_send'] += content
                    # Only send if we didnt have the user connected already
                LOGGED_CLIENTS[uid] = selKey
        else:
            print("Logging out")
            
            uid, selKey, newLogin = message.get_uid_selKey()
            sock = selKey.fileobj
            sel.unregister(sock)
            sock.close()
            if(uid!=""):
                del LOGGED_CLIENTS[uid]
                content = send_lb_logout_info(uid)
                key_lb = sel.get_key(LBSOCK)
                if 'to_send' not in key_lb.data.keys():
                    key_lb.data['to_send'] = b''
                key_lb.data['to_send'] += content
    if mask & selectors.EVENT_WRITE:
        if "to_send" in key.data.keys():
            n = key.fileobj.send(key.data["to_send"])
            key.data['to_send'] = key.data['to_send'][n:]
            if len(key.data['to_send']) == 0:
                del key.data['to_send']


def send_lb_logout_info(uid):
    """Tells the ;pad balancer about which user has logged out
    
    :param uid: user id of the user that has logged out,
    :type uid: str"""
    json_header = {
        "byteorder": sys.byteorder,
        "request": "user-logout",
        "uid": uid,
        "content-length": 0,
    }
    json_header = json.dumps(json_header, ensure_ascii=False).encode(ENCODING_USED)
    return struct.pack('>H', len(json_header)) + json_header

def send_lb_new_login_info(uid, HOST, PORT):
    """Tells the load balancer about which user has logged in
    
    :param uid: User id of the user that has logged in,
    :type uid: str,
    :param HOST: host of the load balancer,
    :type HOST: str,
    :param PORT: port of the load balancer,
    :type PORT: int"""
    json_header = {
        "byteorder": sys.byteorder,
        "request": "new-login",
        "content-length": 0,
        "uid": uid,
        "host": HOST,
        "port": PORT
    }
    json_header = json.dumps(json_header, ensure_ascii=False).encode(ENCODING_USED)
    return struct.pack('>H', len(json_header)) + json_header

def startServer(pvtKey, HOST = "127.0.0.1", PORT = 8000):
    """Server starts and connects to the socket of the load balancer
    
    :param pvtKey: private key of the server,
    :type pvtKey: nacl.public.PrivateKey,
    :param HOST: host of the loadbalancer,
    :type HOST: str,
    :param PORT: port of the loadbalancer,
    :type PORT: int
    """
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
    sel.register(LBSOCK, selectors.EVENT_READ | selectors.EVENT_WRITE, data = {"loadbalancer": lbaddr})
    # print(f"The socket is at {LBSOCK}")
    lsock.listen()

    lsock.setblocking(False)

    
    sel.register(lsock, selectors.EVENT_READ, data = None)
    try:
        while True:
            # print("Reached//")
            events = sel.select(timeout = None)
            for key, mask in events:
                if key.fileobj != LBSOCK:
                    # print('START',key.data,mask)
                    pass
                # print(key.data)
                if key.data is None:
                    accept(sel, key.fileobj)
                else:
                    service(key, mask, HOST, PORT)
    except KeyboardInterrupt as e:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()

if __name__ == "__main__":
    startServer(PrivateKey.generate(), sys.argv[1], int(sys.argv[2]))
