#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket, asyncio, os, http.client

class AppTest:
    def __init__(self, http_port=8080, buffer_size=4096):
        self.http_port = http_port
        self.buffer_size = buffer_size

    async def run_test(self):
        await asyncio.sleep(0.5)
        hc = http.client.HTTPConnection('localhost', self.http_port)
        tilename = '/17/48104/73742.png'

        for test in [
            lambda hc : hc.request('HEAD', '/'),
            lambda hc : hc.request('GET', '/'),
            lambda hc : hc.request('GET', tilename),
        ]:
            request = test(hc)
            print('request')
            await asyncio.sleep(0.2)
            response = hc.getresponse()
            print('-> test -> response', response.status, response.reason)
            assert response.status < 400
            body = response.read(200)
            while not response.closed and (not body == b''):
                print('-> test -> data', body)
                body = response.read(200)
        return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('-> test -> sock.connect((localhost, self.http_port))')
        sock.connect(('localhost', self.http_port))
        with sock:
            await asyncio.sleep(0.1)
            await self.test_root(sock)
            print('\n')
            await self.test_tile(sock, tilename)
            print('\n')
            # rm tilename
            filename = 'tile-cache/'+tilename
            if os.path.exists(filename):
                os.remove(filename)
            await self.test_tile(sock, tilename)
            print('\n')
            try:
                sock.shutdown(socket.SHUT_RDWR)
                while sock.recv(self.buffer_size) != b'':
                    pass
                sock.close()
            except OSError as msg:
                print('-> test -> error on close', msg)
                sock = None
        print('-> test -> test close\n\n\n')

    async def test_root(self, sock):
        request = '\r\n'.join([
                'GET / HTTP/1.1',
                'Host: localhost',
                '\r\n',
        ])
        await asyncio.sleep(0.1)
        print('-> test -> sock.sendall()', request[:30])
        sock.sendall(bytes(request, 'utf8'))
        await asyncio.sleep(0.1)

        response = b''
        while b'\r\n\r\n' not in response:
            await asyncio.sleep(0.1)
            chunk = sock.recv(self.buffer_size)
            print('-> test -> sock.recv()', str(chunk)[:30])
            await asyncio.sleep(0.1)
            response += chunk
            if chunk == b'':
                break
        print('-> test -> TEST REQUEST', request)
        print('-> test -> TEST RESPONSE', response.decode()[:120])

    async def test_double_root(self, sock):
        request = '\r\n'.join([
                'GET / HTTP/1.1',
                'Host: localhost',
                '\r\n',
        ])
        request = request + request
        await asyncio.sleep(0.1)
        print('-> test -> sock.sendall()', request[:30])
        sock.sendall(bytes(request, 'utf8'))
        await asyncio.sleep(0.1)

        response = b''
        while b'\r\n\r\n' not in response:
            await asyncio.sleep(0.1)
            chunk = sock.recv(self.buffer_size)
            print('-> test -> sock.recv()', str(chunk)[:30])
            await asyncio.sleep(0.1)
            response += chunk
            if chunk == b'':
                break
        print('-> test -> TEST REQUEST', request)
        print('-> test -> TEST RESPONSE', response.decode()[:120])


    async def test_tile(self, sock, tilename):
        request = '\r\n'.join([
            'GET /tile/'+tilename+' HTTP/1.1',
            'Host: localhost',
            '\r\n',
        ])
        await asyncio.sleep(0.1)
        print('-> test -> sock.sendall()', request)
        sock.sendall(bytes(request, 'utf8'))
        await asyncio.sleep(0.1)

        response = b''
        while b'\r\n\r\n' not in response:
            await asyncio.sleep(2)
            chunk = sock.recv(self.buffer_size)
            print('-> test -> sock.recv()', str(chunk)[:30])
            await asyncio.sleep(0.1)
            response += chunk
            if (not response == b'') and chunk == b'':
                break
        print('-> test -> test request', request[:30])
        print('-> test -> test response', str(response, 'utf8')[:120])
