import Message
import psycopg2

users_table_name = "Users"

def checkIfUsernameFree(username: str) -> bool:
    """Check if a given username is already in use

    :param username: The username to check
    :type username: str
    :return: Whether the name is in use or not
    :rtype: bool
    """
    conn = psycopg2.connect(database = "testdb", user = "postgres", password = "pass123", host = "127.0.0.1", port = "5432")
    cur = conn.cursor()
    cur.execute(f'''
        SELECT * FROM {users_table_name} WHERE NAME == {username}
    ''')
    names = cur.fetchall()
    conn.close()
    if len(names) == 0:
        return True
    else:
        return False

def createUser(username:str, password:str)->None:
    """Adds a user with the given username and password to the database. Assumes that the checkIfUsernameFree has already been called before. The password is already hashed from the client side. Note that we obviously don't do any salting here

    :param username: username
    :type username: str
    :param password: password (hashed)
    :type password: str
    """
    conn = psycopg2.connect(database = "testdb", user = "postgres", password = "pass123", host = "127.0.0.1", port = "5432")

    cur = conn.cursor()

    cur.execute("INSERT INTO {users_table_name} (NAME, PASSWORD) \
      VALUES ({username}, {password})")

    conn.commit()
    conn.close()
    return


