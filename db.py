import Message
import psycopg2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError 
import nacl
dbName = "mydb"

users_table_name = "Users"
messages_table_name = "Messages"
groups_table_name = "Users"


# Assuming the db passwords etc are the same.
dbUser = "fasty"
dbPass = "pass123"
dbHost = "localhost"
dbPort = 5432
def checkIfUsernameFree(username: str) -> bool:
    """Check if a given username is already in use

    :param username: The username to check
    :type username: str
    :return: Whether the name is in use or not
    :rtype: bool
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT * FROM {users_table_name} WHERE NAME = '{username}'
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) == 0:
        return True
    else:
        return False

def createUser(username:str, password:str, e2ePublicKey:str)->bool:
    """Adds a user with the given username and password to the database. Assumes that the checkIfUsernameFree has already been called before. We hash the password here. Returns true if the user generation happened without any error

    :param username: username
    :type username: str
    :param password: password (hashed)
    :type password: str
    :return: Whether the user creation happened succesfully
    :rtype: bool
    """
    try:
        conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)

        cur = conn.cursor()
        ph = PasswordHasher()
        hashedPassword = ph.hash(password) # Salts and hashes
        cur.execute(f"INSERT INTO {users_table_name} (NAME, PASSWORD, E2EPUBLICKEY) VALUES (\'{username}\', \'{hashedPassword}\', \'{e2ePublicKey}\')")

        conn.commit()
        conn.close()
    except Exception as e:
        print(e)
        return False

    return True


def db_login(username: str, password: str)->bool:
    """Checks if a given username password pair is present in the db

    :param username: username
    :type username: str
    :param password: password
    :type username: str
    :return: True if the user is authenticated by this
    :rtype: bool
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT PASSWORD FROM {users_table_name} WHERE NAME = \'{username}\'
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) == 0:
        return False #username not present
    else:
        ph = PasswordHasher()
        try:
            return ph.verify(names[0][0], password)
            # TODO Update password if needs rehashing https://argon2-cffi.readthedocs.io/en/stable/api.html
        except VerifyMismatchError:
            return False # Password did not match
        return False



def storeMessageInDb(sender: str, receiver: str, message: str, timestamp:str, content_type: str):
    """stores the encrypted message in the database, in case it is not possible to send them the message directly

    :param sender: sender username
    :type sender: str
    :param receiver: receiver username
    :type receiver: str
    :param message: the enecrypted message
    :type message: str
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()

    cur.execute(f'''INSERT INTO {messages_table_name} (SENDER, RECEIVER, MESSAGE, TIMESTAMP, CONTENTTYPE) \
      VALUES (\'{sender}\', \'{receiver}\', \'{message.decode('utf-8')}\', \'{timestamp}\', \'{content_type}\')''')

    conn.commit()
    conn.close()
    return

def getE2EPublicKey(user:str)->str:
    """Takes the username and outputs the e2e public key of that user

    :param user: username of the user
    :type user: str
    :return: the e2ekey in base64
    :rtype: str
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT E2EPUBLICKEY FROM {users_table_name} WHERE NAME = '{user}'
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) == 0:
        return None
    else:
        return names[0][0]

def getUnsentMessages(username: str)->list:
    """Get the unsent messages to a particular user, ordered by timestamp

    :param username: username of receiver
    :type username: str
    :return: list of tuples containing the data about the messages
    :rtype: list
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()

    cur.execute(f'''SELECT * FROM {messages_table_name} \
      WHERE RECEIVER LIKE \'%::{username}\' ORDER BY TIMESTAMP''')
    messages = cur.fetchall()
    conn.commit()
    conn.close()
    return messages


def checkIfGroupNameFree(groupName: str)-> bool:
    """Check if a given groupname is already in use

    :param groupName: The groupname to check
    :type username: str
    :return: Whether the name is in use or not
    :rtype: bool
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT * FROM {groups_table_name} WHERE NAME = '{groupName}'
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) == 0:
        return True
    else:
        return False
 

def createGroup(groupname:str, key:str, creatorUsername:str)->bool:
    try:
        conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)

        cur = conn.cursor()
        cur.execute(f"INSERT INTO {groups_table_name} (GROUPNAME, KEY, CREATOR) VALUES (\'{groupname}\', \'{key}\', \'{creatorUsername}\')")

        conn.commit()
        conn.close()
    except Exception as e:
        print(e)
        return False

    return True
