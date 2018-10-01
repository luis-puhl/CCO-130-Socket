#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from HttpServer import HttpServer

class App:
    def __init__(self, host='localhost', port=8080):
        callback = self.route
        self.httpserver = HttpServer(callback, host, port)
        self.listen()

    def listen(self):
        self.httpserver.listen()

    def route(self, headers=(), body=b''):
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
            staus: 'HTTP/1.1 302 Found',
            headers: {
                'Location': '/index.html?zoom=17&lat=-21.98046&lon=-47.88036',
            },
            body: '',
        }
        return response

    def index(self, request):
        pass

    def close():
        pass
