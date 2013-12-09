#!/usr/bin/env python2.7

# Still needs better error handling in the main loop.

import os, socket

port = 8001
cache_location = "/tmp/krb5cc_agent_{0}".format(os.getuid())
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

def do_kinit(client_principal):
    return os.system("kinit -c {0} {1}".format(cache_location, client_principal))

def do_ticket(server_principal):
    return os.system("kvno -c {0} {1}".format(cache_location, server_principal))

try:
    sock.bind(('', port))
    sock.listen(0)
    while True:
        conn, addr = sock.accept()
        print("Received socket connection from {0}".format(addr))
        full_msg, length = get_full_msg(conn)
        cmd, arg = full_msg.split('\n', 1)
        print("Message decoded: {0} {1}".format(cmd, arg))
        if cmd == "kinit":
            if do_kinit(arg) == 0:
                print("kinit successful")
                conn.send("OK")
            else:
                print("kinit failed")
                conn.send("FAIL")
        elif cmd == "ticket":
            if do_ticket(arg) == 0:
                os.system("kserialize {0} {1} {2}".format(cache_location, arg,
                                                          service_ticket_location))
                tkt = open(service_ticket_location, 'r').read()
                print("Sending ticket: {0} {1}".format(len(tkt), tkt))
                conn.send("{0}\n{1}".format(len(tkt), tkt))
            else:
                print("Ticket request failed")
                conn.send("FAIL")
except (IOError, KeyboardInterrupt) as e:
    sock.close()
    exit()
