#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
import asyncio

class AppTest:
    def __init__(self, http_port=8080, buffer_size=4096):
        self.http_port = http_port
        self.buffer_size = buffer_size

    async def run_test(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('-> test -> sock.connect((localhost, self.http_port))')
        sock.connect(('localhost', self.http_port))
        await asyncio.sleep(0.1)

        request = '\r\n'.join([
            'GET / HTTP/1.1',
            'Host: localhost',
            '\r\n',
        ])
        await asyncio.sleep(0.1)
        print('-> test -> sock.sendall(bytes(request, utf8))')
        sock.sendall(bytes(request, 'utf8'))
        await asyncio.sleep(0.1)

        response = b''
        while b'\r\n\r\n' not in response:
            print('-> test -> sock.recv(self.buffer_size)')
            await asyncio.sleep(0.1)
            chunk = sock.recv(self.buffer_size)
            await asyncio.sleep(0.1)
            response += chunk
        print('-> test -> test request', request)
        print('-> test -> test response', str(response))
        sock.shutdown(socket.SHUT_RDWR)
        while sock.recv(self.buffer_size) != b'':
            pass
        sock.close()
        print('-> test -> test close')
