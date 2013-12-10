#!/usr/bin/env python2.7

import os, socket

port = 8001
cache_location = "/tmp/krb5cc_agent_{0}".format(os.getuid())
service_ticket_location = "/tmp/service_ticket"

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def get_message(conn):
    """Read in a message that looks like "length\nmessage" from conn."""
    length, message = conn.recv(1024).split('\n', 1)
    while int(length) != len(message):
        msg = conn.recv(1024)
        if not msg:
            raise ValueError("Socket message was not long enough")
        message += msg
    return message

def do_kinit(client_principal):
    return os.system("kinit -c {0} {1}".format(cache_location, client_principal))
def do_ticket(server_principal):
    return os.system("kvno -c {0} {1}".format(cache_location, server_principal))
def do_kdestroy():
    return os.system("kdestroy -c {0}".format(cache_location))

sock.bind(('', port))
sock.listen(0)
while True:
    try:
        conn, addr = sock.accept()
        print("Received socket connection from {0[0]}:{0[1]}".format(addr))
        cmd, arg = get_message(conn).split('\n', 1)
        print("Message decoded: {0} {1}".format(cmd, arg))
        if cmd == "kinit":
            if do_kinit(arg) == 0:
                print("kinit successful")
                conn.send("OK")
            else:
                print("kinit failed")
                conn.send("FAIL")
        elif cmd == "ticket":
            if (not arg.startswith('krbtgt')) and do_ticket(arg) == 0:
                os.system("kserialize {0} {1} {2}".format(cache_location, arg,
                                                          service_ticket_location))
                tkt = open(service_ticket_location, 'r').read()
                print("Sending ticket: {0} bytes".format(len(tkt)))
                conn.send("{0}\n{1}".format(len(tkt), tkt))
            else:
                print("Ticket request failed")
                conn.send("FAIL")
        elif cmd == "kdestroy":
            do_kdestroy()
        else:
            print("Unimplemented command \"{0}\"".format(cmd))
    except IOError:
        print("Something bad happened over the socket.")
    except KeyboardInterrupt:
        exit()
    except:
        print("An unknown error occurred.")
