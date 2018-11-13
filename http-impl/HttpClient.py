#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from TcpConnection import TcpConnection
from HttpBase import HTTP_REQ_VERBS, HTTP_REQ_VERBS_HAS_BODY, HTTP_RES_STATUS

class HttpClient:
    def __init__(self, host='localhost', port=80):
        self.host = host
        self.port = port
        self.tcpClient = TcpConnection()
        self.tcpClient.connect(host, port)
        print('HttpClient connect:', host, port)

    async def send_request(method, path, headers, body=b''):
        """
        GET / HTTP/1.1
        Host: developer.mozilla.org
        Accept-Language: fr
        """
        assert method in HTTP_REQ_VERBS
        req_line = (method + ' ' +  path + ' HTTP/1.1').encode()
        req_headers = b''
        req_body = body.encode()

        nowtime = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %Z").encode()
        host = self.host
        if not self.port == 80:
            host = host + ':' + self.port
        headers[b'Host'] = host.encode()
        if not b'Content-Length' in headers:
            headers[b'Content-Length'] = len(req_body)
        for key in headers:
            value = headers[key]
            if isinstance(value, int):
                value = str(value)
            if isinstance(key, str):
                key = key.encode()
            if isinstance(value, str):
                value = value.encode()
            req_headers += key + b': ' + value + b'\r\n'

        raw_request = req_line + b'\r\n' + req_headers + b'\r\n' + req_body

        await self.tcpClient.send(raw_request)

        return await self.rcv_response()

    async def rcv_response(self):
        raw_response = b''
        # request head not here yet
        while not (b'\r\n\r\n' in raw_response or b'\n\n' in raw_response):
            raw_response += await self.tcpClient.recv(4096)
            print('HttpClient async def rcv_response', raw_response)
            if not raw_response or raw_response == b'':
                # connection ended
                self.tcpClient.close()
                return
        respSplit = raw_response.split(b'\r\n\r\n')
        raw_head = respSplit[0]
        raw_body = b''.join(respSplit[1:])
        raw_head_split = raw_head.splitlines()

        status = raw_head_split[0].split(b' ')
        headers = dict([i.split(b': ') for i in raw_head_split[1:]])
        if headers.get(b'Content-Length'):
            content_length = headers.get(b'Content-Length', 0)
            while not len(raw_body) == content_length:
                tail = await self.tcpClient.recv(4096)
                raw_response += tail
                raw_body += tail

        content_type = headers.get(b'content-type', b'text/plain; charset=UTF-8')
        if b'text' in content_type:
            body = raw_body.decode()
        else:
            body = raw_body
        print('HttpClient ', status, headers, body)
        return status, headers, body

    def close():
        pass
