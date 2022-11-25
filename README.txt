We have successfully implemented secure end to end encrypted single server, multiple client architecture,
for private and group chats, supporting both messsage and file exchange

Tech Stack Used:
    postgresql
    pynacl
    sockets

Procedure To Run:
    Set up postgres database:
        Run the commands in `sqlCommandsInit.txt`
    Run loadbalancer.py in the ServerSide Repository
    Run app.py as many times as you want in the ClientSide Repository

Note that loadbalancer.py 
Team Members Contribution: 
    Khushang: Client Side Programming
    Mridul: Server Side Programming
    Arhaan: Database Handling
