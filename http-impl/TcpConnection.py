#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket

class TcpConnection:
    def __init__(self, remote_host='localhost', remote_port=8080):
        # The address family should be AF_INET (the default), AF_INET6, AF_UNIX, AF_CAN, AF_PACKET, or AF_RDS.
        # The socket type should be SOCK_STREAM (the default), SOCK_DGRAM, SOCK_RAW or perhaps one of the other SOCK_ constants.
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        # setsockopt(level, optname, value: int), Unix manual page setsockopt(2)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def recv(self, buffer_size=4096):
        return self.sock.rcv(buffer_size)

    def send(self, data=b''):
        return self.sock.send(data)

    def sendAll(self, data=b''):
        return self.send(data)

    def shutdown(self, mode=socket.SHUT_RDWR):
        return self.sock.shutdown(mode)

    def close(self):
        return self.sock.close()

    def setsockopt(self, level=socket.SOL_SOCKET, optname=socket.SO_REUSEADDR, value=1):
        return self.sock.setsockopt(level, optname, value)

    def setblocking(self, is_blocking=True):
        return self.sock.setblocking(is_blocking)

    def bind(self, host, port):
        return self.sock.bind((host, port))

    def listen(self, segmets_backlog=5):
        # Enable a server to accept connections.
        # If backlog is specified, it must be at least 0 (if it is lower, it is set to 0);
        # it specifies the number of unaccepted connections that the system will allow before refusing new connections.
        # If not specified, a default reasonable value is chosen.
        return self.sock.listen(segmets_backlog)

    def accept(self):
        return self.sock.accept()
