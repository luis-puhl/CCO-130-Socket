#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from TcpConnection import TcpConnection
import select

class HttpServer:
    def __init__(self, callback, host='localhost', port=8080):
        self.callback = callback

        # sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcpServer = TcpConnection('', 80)

        self.tcpServer.setblocking(0)
        self.tcpServer.bind(host, port)
        print('listening:', port)
        pass

    def send_response(headers={}, body=b''):
        pass

    def recv(self, request):
        req_headers, req_body = self.parse_request(request)
        res_headers, res_body = self.route(req_headers, req_body)
        response = self.build_response(res_headers, res_body)
        HttpServer.send(response)

    def revieve_request(sock):
        headers = {}
        body = b''
        return headers, body

    def loop():
        req_headers, req_body = self.revieve_request()
        res_headers, res_body = self.callback(req_headers, req_body)
        self.send_response(res_headers, res_body)

    def listen(self):
        # emtpy list
        self.clients = []
        # empty dic
        self.reqs = {}
        self.tcpServer.listen()
        out_flag = False
        while not out_flag:
            # rlist: wait until ready for reading
            # wlist: wait until ready for writing
            # xlist: wait for an “exceptional condition” (see the manual page for what your system considers such a condition)
            rlist, wlist, xlist = select.select(self.clients + [self.tcpServer.sock], [], [])
            for cli in rlist:
                if cli == self.tcpServer.sock:
                    cli, addr = cli.accept()
                    cli.setblocking(0)
                    self.clients.append(cli)
                    self.reqs[cli] = b''
                else:
                    self.reqs[cli] += cli.recv(1500)
                    req = self.reqs[cli]
                    if b'\r\n\r\n' in req or b'\n\n' in req:
                        method, path, lixo = req.split(b' ', 2)
                        if method == b'GET':
                            texto = b"Hello " + path
                        else:
                            texto = b"Num entendi"
                        print(method, path)
                        if path == b'/out':
                            out_flag = True
                        resp = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(texto)
                        resp += texto
                        # note que um bom servidor usaria também a wlist e enviaria a resposta por pedaços
                        cli.send(resp)
                        cli.close()
                        del self.reqs[cli]
                        self.clients.remove(cli)

        self.tcpServer.close()
        print('<conexao fechada>')
