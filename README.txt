We have successfully implemented secure end to end encrypted single server, multiple client architecture,
for private and group chats, supporting both messsage and file exchange

Tech Stack Used:
    postgresql
    pynacl
    sockets

Procedure To Run:
    Set up postgres database:
        CREATE USER fasty with PASSWORD 'pass123';
        CREATE DATABASE mydb;
        GRANT ALL PRIVILEGES ON DATABASE mydb TO fasty;
        \c mydb fasty
        CREATE TABLE IF NOT EXISTS Users(NAME TEXT UNIQUE NOT NULL, PASSWORD TEXT NOT NULL, E2EPUBLICKEY TEXT NOT NULL);
        CREATE TABLE MESSAGES(SENDER TEXT NOT NULL, RECEIVER TEXT NOT NULL, MESSAGE TEXT NOT NULL, TIMESTAMP FLOAT NOT NULL, CONTENTTYPE TEXT NOT NULL);
        CREATE TABLE GROUPS (GROUPNAME TEXT NOT NULL, CREATOR TEXT NOT NULL, CREATORKEY TEXT NOT NULL);
        CREATE TABLE GROUPMEMBERS (GROUPNAME TEXT NOT NULL, KEY TEXT NOT NULL, USERNAME TEXT NOT NULL);
    Run startServer.py in ServerSide Repository
    Run app.py as many times as you want in ClientSide Repository

Yet to be done:
    Load Balancing and shifting to multiple Servers
    Performance Analysis


Team Members Contribution: 
    Khushang: Client Side Programming
    Mridul: Server Side Programming
    Arhaan: Database Handling
