import Message
import psycopg2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError 
import nacl
import datetime
from typing import List, Tuple
dbName = "mydb"

users_table_name = "Users"
messages_table_name = "Messages"
groups_table_name = "Groups"
groups_members_table_name = "GroupMembers"


# Assuming the db passwords etc are the same.
dbUser = "fasty"
dbPass = "pass123"
dbHost = "localhost"
dbPort = 5432

def deleteOldMessages():
    """Delete messages older than 7 days (can change later)
    This is called when we add some new message to the db
    """
    lastTimeStampToKeep = datetime.datetime.timestamp(datetime.datetime.now() - datetime.timedelta(days=7))
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''DELETE FROM {messages_table_name} \
      WHERE TIMESTAMP < {lastTimeStampToKeep}
      ''')
    conn.commit()
    conn.close()
    return




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
    deleteOldMessages()
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
    keys = cur.fetchall()
    conn.close()
    if len(keys) == 0:
        return None
    else:
        return keys[0][0]

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
      WHERE RECEIVER='{username}' OR RECEIVER LIKE \'%::{username}\' ORDER BY TIMESTAMP''')
    messages = cur.fetchall()
    cur.execute(f'''DELETE FROM {messages_table_name} \
      WHERE RECEIVER='{username}'
      ''')
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
        SELECT * FROM {groups_table_name} WHERE GROUPNAME = '{groupName}'
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) == 0:
        return True
    else:
        return False
 
def createGroup(groupname:str, key:str, creatorUsername:str, creatorE2Ekey: str)->bool:
    """Creates a new group in the database

    :param groupname: name of the group
    :type groupname: str
    :param key: key used for encrypting messages for this group. Note that this is encrypted by the creators e2e encrypted key
    :type key: str
    :param creatorUsername: username of creator
    :type creatorUsername: str
    :return: _description_
    :rtype: bool
    """
    try:
        conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)

        cur = conn.cursor()
        cur.execute(f"INSERT INTO {groups_table_name} (GROUPNAME, CREATOR, CREATORKEY) VALUES (\'{groupname}\', \'{creatorUsername}\', '{creatorE2Ekey}')")
        cur.execute(f"INSERT INTO {groups_members_table_name} (GROUPNAME, KEY, USERNAME) VALUES (\'{groupname}\', \'{key}\', \'{creatorUsername}\')")

        conn.commit()
        conn.close()
    except Exception as e:
        print(e)
        return False

    return True

def isGroupAdmin(groupName:str, username:str)->bool:
    """Checks if a particular user is the admin of a group

    :param groupName: name of the group
    :type groupName: str
    :param username: username to check
    :type username: str
    :return: whether username is an admin of the group
    :rtype: bool
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT * FROM {groups_table_name} WHERE GROUPNAME = '{groupName}' AND CREATOR = '{username}'
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) != 0:
        return True
    else:
        return False

def addUserToGroup(groupname: str, username: str,usersGroupKey: str):
    try:
        print("Adding user to group")
        conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
        cur = conn.cursor()
        cur.execute(f"INSERT INTO {groups_members_table_name} (GROUPNAME, KEY, USERNAME) VALUES (\'{groupname}\', \'{usersGroupKey}\', \'{username}\')")
        conn.commit()
        conn.close()
    except Exception as e:
        print(e)
        return False

    return True

def getGroupMembers(groupname: str)->List[str]:
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT USERNAME FROM {groups_members_table_name} WHERE GROUPNAME = '{groupname}'
    ''')
    names = cur.fetchall()
    names = list(list(zip(*names))[0])
    return names
 
def getUsersGroupKey(groupname: str, username: str)-> Tuple[str, str]:
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        SELECT KEY FROM {groups_members_table_name} WHERE GROUPNAME = '{groupname}' and USERNAME ='{username}'
    ''')
    
    keys = cur.fetchall()
    if len(keys) == 0:
        return "", "" # User not in group
    encryptedGroupUserKey = keys[0][0]
    cur.execute(f'''
        SELECT CREATORKEY FROM {groups_table_name} WHERE GROUPNAME = '{groupname}'
    ''')
    keys = cur.fetchall()
    creatorE2EKey = keys[0][0]
    return encryptedGroupUserKey, creatorE2EKey

def removeGroupMember(groupname: str, username: str):
    """Remove a user from the db of a group

    :param groupname: name of the group
    :type groupname: str
    :param username: username to remove
    :type username: str
    """
    conn = psycopg2.connect(database = dbName, user = dbUser, password = dbPass, host = dbHost, port = dbPort)
    cur = conn.cursor()
    cur.execute(f'''
        DELETE FROM {groups_members_table_name} WHERE GROUPNAME = '{groupname}' and USERNAME ='{username}'
    ''')
    conn.commit()
    conn.close()
