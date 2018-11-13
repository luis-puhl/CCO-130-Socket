#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from TcpConnection import TcpConnection
from datetime import datetime
import select
import asyncio
from HttpBase import HTTP_REQ_VERBS, HTTP_REQ_VERBS_HAS_BODY, HTTP_RES_STATUS

class HttpServer:
    def __init__(self, callback, host='localhost', port=8080):
        self.callback = callback
        self.tcpServer = TcpConnection()
        self.tcpServer.setblocking(0)
        self.tcpServer.bind(host, port)
        print('HttpServer listening:', port)
        pass

    async def shutdown(self):
        print('HttpServer  shutdown')
        self.out_flag = True
        print('HttpServer out_flag', self.out_flag)
        await asyncio.sleep(0.1)

    def select(self, rlist, wlist, xlist):
        # rlist: wait until ready for reading
        # wlist: wait until ready for writing
        # xlist: wait for an “exceptional condition” (see the manual page for what your system considers such a condition)
        # print('HttpServer select')
        return select.select(rlist, wlist, xlist, 0.1)


    async def listen(self):
        # emtpy list
        self.clients = []
        # empty dic
        self.reqs = {}
        self.tcpServer.listen()

        self.out_flag = False
        while not self.out_flag:
            await asyncio.sleep(0.0001)
            try:
                rlist, wlist, xlist = self.select(self.clients + [self.tcpServer], [], [])
                for cli in rlist:
                    print('HttpServer http server loop read cli')
                    if cli == self.tcpServer:
                        cli = self.tcpServer
                        cli, addr = cli.accept()
                        cli.setblocking(0)
                        print('HttpServer Nova conexão')
                        self.clients.append(cli)
                        self.reqs[cli] = b''
                    else:
                        await asyncio.wait_for(self.read_cli(cli), timeout=1)
            except asyncio.TimeoutError:
                print('timeout!')

        print('HttpServer  out_flag', self.out_flag)
        for cli in self.clients:
            self.close_cli(cli)
        self.close_cli(self.tcpServer)
        print('HttpServer <server parado>')

    async def read_cli(self, cli):
        print('HttpServer read_cli')
        self.reqs[cli] += await cli.recv(4096)
        resquest = self.reqs[cli]
        if not resquest or resquest == b'':
            # connection ended
            self.close_cli(cli)
            return
        if not (b'\r\n\r\n' in resquest or b'\n\n' in resquest):
            # request head not here yet
            return
        print('HttpServer header received', resquest.decode()[:40])

        # spit req
        req_line, req_headers, req_body = self.split_raw_request(resquest)
        while b'Content-Length' in req_headers and req_headers[b'Content-Length'] > len(body):
            self.reqs[cli] += await cli.recv(4096)
            resquest = self.reqs[cli]
            req_line, req_headers, req_body = self.split_raw_request(resquest)
        while b'Content-Length' in req_headers and req_headers[b'Content-Length'] > len(body):
            self.reqs[cli] = b''
        method, path, version = req_line
        # process
        response = self.callback(req_line, req_headers, req_body)
        if asyncio.iscoroutine(response):
            response = await asyncio.gather(response)
        status_code, headers, body = response
        status = HTTP_RES_STATUS[status_code]
        # join res
        if not HTTP_REQ_VERBS_HAS_BODY[method.decode()]:
            body = b''
        raw_response = self.join_raw_response(status, headers, body)
        print('HttpServer (raw_response)', raw_response.decode()[:40])

        n = 4096
        segs = int(len(raw_response) / n)
        for i in range(0, segs+1):
            if i > segs:
                seg = raw_response[i*n:]
            else:
                seg = raw_response[i*n:i*n+n]
            print('HttpServer seg', seg)
            if cli.
            await cli.send(seg)

        # self.close_cli(cli)
        return

    def close_cli(self, cli):
        print('HttpServer cli connection ended')
        cli.shutdown()
        cli.close()
        del self.reqs[cli]
        self.clients.remove(cli)

    def split_raw_request(self, raw_request):
        resqSplit = raw_request.split(b'\r\n\r\n')
        raw_head = resqSplit[0]
        raw_body = b''.join(resqSplit[1:])
        raw_head_split = raw_head.splitlines()

        resquest_line = raw_head_split[0].split(b' ')
        header_fields = dict([i.split(b': ') for i in raw_head_split[1:]])
        body = raw_body
        print('HttpServer ', resquest_line, header_fields, body)
        return resquest_line, header_fields, body

    def join_raw_response(self, status, headers, body):
        if not b'HTTP' in status:
            status = b'HTTP/1.1 404 Not Found',

        nowtime = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z").encode()
        if not b'Date' in headers:
            # headers[b'Date'] = 'Mon, 01 Oct 2018 14:52:12 GMT'
            headers[b'Date'] = nowtime
        if not b'last-modified' in headers:
            headers[b'last-modified'] = nowtime
        if not b'cache-control' in headers:
            headers[b'cache-control'] = b'max-age=3600'
        if not b'server' in headers:
            headers[b'server'] = b'marreco de latex'
        if not b'Connection' in headers:
            headers[b'Connection'] = b'keep-alive'

        if not b'Content-Length' in headers:
            headers[b'Content-Length'] = len(body)

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
