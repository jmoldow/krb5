#!/usr/bin/env python2.7

# Basic starting code for the agent
# Set up for testing, doesn't handle errors well yet

import os, os.path
import socket

# for testing/demo, can make this an argument later
sock_path = "localhost"
sock_port = 8001
uid = os.getuid()
# can implement setting a different location later if we care
cache_location = "/tmp/krb5cc_agent_"+str(uid)
service_ticket_location = "/tmp/service_ticket"

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def get_full_msg(conn):
    """
    Reads in a complete message from |conn|. This method handles the protocol
    "length\nmsg" by continuing to read from the socket until we have assembled
    a message of the appropriate length.
    """
    full_msg = ""
    length = -1
    while length != 0:
        msg = conn.recv(1024)
        print "recv:", msg
        if not msg:
            raise ValueError("No input received over socket")
        full_msg += msg
        if length < 0 and full_msg.find('\n') >= 0:
            # initialize length
            length_str, rem = full_msg.split('\n', 1)
            full_msg = rem
            length = int(length_str) - len(rem)
        elif length > 0:
            length -= len(msg)
    return (full_msg, length)

def kinit(principal):
    return os.system("kinit -c "+cache_location+" "+principal)

def get_tkt(server_principal):
    command = "kvno -c "+cache_location+" "+server_principal
    print command
    return os.system(command)


try:
    sock.bind((sock_path, sock_port))
    sock.listen(0)
    while True:
        conn, addr = sock.accept()

        # read and assemble the message
        full_msg, length = get_full_msg(conn)
        cmd, arg = full_msg.split('\n', 1)
        
        if cmd == "kinit":
            principal = arg
            creds = kinit(principal)
            if creds == 0:
                conn.send("OK")
            else:
                conn.send("FAIL")
        elif cmd == "ticket":
            server_principal = arg
            status = get_tkt(server_principal)
            if status == 0:
                if os.path.isfile(service_ticket_location):
                    os.remove(service_ticket_location)
                kserialize_cmd = "kserialize "+cache_location+" "+ \
                    server_principal+" "+service_ticket_location
                print kserialize_cmd
                os.system(kserialize_cmd)

                f = open(service_ticket_location, 'r')
                tkt = f.read()
                print "Sending ticket: %d, %s" % (len(tkt), tkt)
                conn.send("%d\n%s" % (len(tkt), tkt))
            else:
                print "FAIL"
                conn.send("FAIL")
except (IOError, KeyboardInterrupt) as e:
    sock.close()
    exit()
            
    

