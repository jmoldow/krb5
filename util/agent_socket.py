# Basic starting code for the agent
# Set up for testing, doesn't handle errors well yet

import socket
import os, os.path

# for testing/demo, can make this an argument later
sock_path = "localhost"
sock_port = 8001
uid = os.getuid()
# can implement setting a different location later if we care
cache_location = "/tmp/krb5cc_agent_"+str(uid)

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

def get_rest_of_msg(conn, length, msg):
    still_need = length -1024
    while still_need > 0:
        msg_continued = conn.recv(1024)
        msg = msg + msg_continued
        still_need = still_need - 1024
    return msg

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
        # hopefully big enough to get whole message in one read
        msg = conn.recv(1024)
        if not msg:
            break
        else:
            tokens = msg.split('\n', 2)
            if tokens[1] == "kinit":
                # length calculation: tokens[0] = len(tokens[1])+len(principal)+2
                # and we still need to read tokens[0]+len(tokens[0])+1-1024
                principal = get_rest_of_msg(conn, int(tokens[0]) + \
                                                len(tokens[0])+1, tokens[2])
                creds = kinit(principal)
                if creds == 0:
                    conn.send("OK")
                else:
                    conn.send("FAIL")
            elif tokens[1] == "ticket":
                server_principal = get_rest_of_msg(conn, int(tokens[0])+ \
                                                       len(tokens[0])+1, tokens[2])
                status = get_tkt(server_principal)
                if status == 0:
                    ## For testing, change this line to point to
                    ## your compiled kcpytkt
                    os.system("kcpytkt -c "+cache_location+" "+ \
                                  "/tmp/service_ticket "+server_principal)
                                 "/tmp/service_ticket "+server_principal)

                    f = open("/tmp/service_ticket", 'r')
                    conn.send(f.read())
                else:
                    conn.send("FAIL")
except IOError, KeyboardInterrupt:
    sock.close()
    exit()
            
    

