#!/usr/bin/env python

import socket

sock_path = "localhost"
sock_port = 8001

sock = socket.socket()

sock.connect((sock_path, sock_port))
msg = "kinit\ngurtej@ATHENA.MIT.EDU"
sock.send(str(len(msg))+"\n"+msg)
print sock.recv(1024)
sock.shutdown(socket.SHUT_RDWR)
sock.close()

sock = socket.socket()

sock.connect((sock_path, sock_port))
msg = "ticket\nhost/linerva.mit.edu@ATHENA.MIT.EDU"
sock.send(str(len(msg))+"\n"+msg)
print sock.recv(1024)
