#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from HttpServer import HttpServer
import threading

class App(threading.Thread):
    def __init__(self, host='localhost', port=8080):
        callback = self.route
        self.httpserver = HttpServer(callback, host, port)

        self.threadLock = threading.Lock()

        threading.Thread.__init__(self)

    def run(self):
        self.listen()
        # try:
        #     self.listen()
        # except Exception as error:
        #     print('error', error)
        #     raise error

    def shutdown(self):
        print('App shutdown')
        self.httpserver.shutdown()

    def listen(self):
        self.httpserver.listen()

    def route(self, req_line={}, req_headers={}, req_body=b''):
        staus, headers, body = self.echo_http(req_line, req_headers, req_body)
        print('(staus, headers, body)', staus, headers, body)
        return staus, headers, body

        location = headers.get('Location')
        routes = {
            '/':                                                self.root,
            '/index.html?zoom=[0-9]+&lat=[0-9]+&lon=[0-9]+':    self.index,
            '/tile/[0-9]+/[0-9]+/[0-9]+.png':                   self.tile,
            'default':                                          self.static_file,
        }
        for route in routes:
            matched_route = routes[route]
            if matched_route and re.match(matched_route.pattern, location):
                response_headers, response_body = matched_route(headers, body)
                return response_headers, response_body

        response_headers, response_body = routes['default'](headers, body)
        return response_headers, response_body

    def root(self, request):
        response = {
            staus: b'HTTP/1.1 302 Found',
            headers: {
                b'Location': b'/index.html?zoom=17&lat=-21.98046&lon=-47.88036',
            },
            body: '',
        }
        return response

    def index(self, request):
        pass

    def echo_http(self, req_line, headers, body):
        method, path, version = req_line
        if method == b'GET':
            texto = b"Hello " + path
        else:
            texto = b"Num entendi"
        # resp = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(texto)
        # resp += texto

        staus = b'HTTP/1.1 200 OK'
        headers = {}
        body = texto
        return staus, headers, body

    def close():
        pass
