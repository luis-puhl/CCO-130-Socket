#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from TcpConnection import TcpConnection
import select

HTTP_REQ_VERBS = {
    'GET': 'GET',
    'HEAD': 'HEAD',
    'POST': 'POST',
    'PUT': 'PUT',
    'DELETE': 'DELETE',
    'CONNECT': 'CONNECT',
    'OPTIONS': 'OPTIONS',
    'TRACE': 'TRACE',
    'PATCH': 'PATCH',
}
HTTP_REQ_VERBS_HAS_BODY = {
    'GET': 'OPTIONAL',
    'HEAD': False,
    'POST': True,
    'PUT': True,
    'DELETE': False,
    'CONNECT': True,
    'OPTIONS': 'OPTIONAL',
    'TRACE': False,
    'PATCH': True,
}

class HttpServer:
    def __init__(self, callback, host='localhost', port=8080):
        self.callback = callback

        # sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcpServer = TcpConnection()

        self.tcpServer.setblocking(0)
        self.tcpServer.bind(host, port)
        print('listening:', port)
        pass

    def shutdown(self):
        print('HttpServer shutdown')
        self.out_flag = True
        print('out_flag', out_flag)


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

        self.out_flag = False
        while not self.out_flag:
            # rlist: wait until ready for reading
            # wlist: wait until ready for writing
            # xlist: wait for an “exceptional condition” (see the manual page for what your system considers such a condition)
            rlist, wlist, xlist = select.select(self.clients + [self.tcpServer], [], [])
            for cli in rlist:
                if cli == self.tcpServer:
                    cli = self.tcpServer
                    cli, addr = cli.accept()
                    cli.setblocking(0)
                    print('Nova conexão')
                    self.clients.append(cli)
                    self.reqs[cli] = b''
                else:
                    self.read_cli(cli)

        print('HttpServer out_flag')
        for cli in self.clients:
            self.close_cli(cli)
        self.close_cli(self.tcpServer)
        print('<server parado>')

    def read_cli(self, cli):
        self.reqs[cli] += cli.recv(4096)
        resquest = self.reqs[cli]
        if not resquest or resquest == b'':
            # connection ended
            self.close_cli(cli)
            return
        if not (b'\r\n\r\n' in resquest or b'\n\n' in resquest):
            # request head not here yet
            return

        # spit req
        req_line, req_headers, req_body = self.split_raw_request(resquest)
        # print('(req_line, req_headers, req_body)', req_line, req_headers, req_body)
        # process
        staus, headers, body = self.callback(req_line, req_headers, req_body)
        print('(staus, headers, body)', staus, headers, body)
        # join res
        raw_response = self.join_raw_response(staus, headers, body)
        print('(raw_response)', raw_response)

        n = 4096
        segs = int(len(raw_response) / n)
        for i in range(0, segs+1):
            if i > segs:
                seg = raw_response[i*n:]
            else:
                seg = raw_response[i*n:i*n+n]
            print('seg', seg)
            cli.send(seg)

        self.close_cli(cli)
        return

    def close_cli(self, cli):
        print('cli connection ended')
        cli.shutdown()
        cli.close()
        del self.reqs[cli]
        self.clients.remove(cli)


    def funcname(self, parameter_list):
        if b'\r\n\r\n' in resquest or b'\n\n' in resquest:
            response_headers
            response_body
            method, path, tail = resquest.split(b' ', 2)
            tail.split
            b'Content-Length: '
            b'\r\n'
            if method == b'GET':
                texto = b"Hello " + path
            else:
                texto = b"Num entendi"
            print(method, path)
            if path == b'/out':
                out_flag = True

            # note que um bom servidor usaria também a wlist e enviaria a resposta por pedaços
            cli.send(resp)
            cli.close()
            del self.reqs[cli]
            self.clients.remove(cli)
            pass

    def split_raw_request(self, raw_request):
        resqSplit = raw_request.split(b'\r\n\r\n')
        raw_head = resqSplit[0]
        raw_body = b''.join(resqSplit[1:])
        raw_head_split = raw_head.splitlines()

        resquest_line = raw_head_split[0].split(b' ')
        header_fields = dict([i.split(b': ') for i in raw_head_split[1:]])
        body = raw_body
        print(resquest_line, header_fields, body)
        return resquest_line, header_fields, body

    def join_raw_response(self, status, headers, body):
        if not b'HTTP' in status:
            status = b'HTTP/1.1 404 Not Found',

        if not b'Date: ' in headers:
            headers[b'Date'] = 'Mon, 01 Oct 2018 14:52:12 GMT'
        if not b'server: ' in headers:
            headers[b'server'] = 'ecstatic-3.2.0'
        if not b'Connection: ' in headers:
            headers[b'Connection'] = 'keep-alive'

        if not b'Content-Length: ' in headers:
            headers[b'Content-Length: '] = len(body)

        raw_response = b''
        raw_response += status + b'\r\n'
        for key in headers:
            value = headers[key]
            if isinstance(value, int):
                value = str(value)
            if isinstance(key, str):
                key = key.encode()
            if isinstance(value, str):
                value = value.encode()
            raw_response += key + b': ' + value + b'\r\n'

        raw_response += b'\r\n'
        if len(body) > 0:
            raw_response += body

        return raw_response
