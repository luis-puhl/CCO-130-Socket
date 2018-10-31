#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from HttpServer import HttpServer
import re
import os

class App:
    def __init__(self, host='localhost', port=8080):
        callback = self.route
        self.httpserver = HttpServer(callback, host, port)

    async def shutdown(self):
        print('App App shutdown')
        await self.httpserver.shutdown()

    async def listen(self):
        await self.httpserver.listen()

    def route(self, req_line={}, req_headers={}, req_body=b''):
        # staus, headers, body = self.echo_http(req_line, req_headers, req_body)
        # print('App (staus, headers, body)', staus, headers, body)
        # return staus, headers, body

        method, path, version = req_line
        path_str = path.decode()
        routes = {
            '/echo.*':                          self.echo_http,
            '/index.*':                         self.index,
            '/tile/[0-9]+/[0-9]+/[0-9]+.png':   self.tile,
            '/':                                self.root,
            'default':                          self.static_file,
        }
        for route_key, route_fn in routes.items():
            if route_fn and re.match('^' + route_key + '$', path_str):
                print('\nApp route match "{0}" => "{1}"'.format(route_key, path_str))
                status, headers, body = route_fn(req_line, req_headers, req_body)
                return status, headers, body

        route_key = 'default'
        print('\nApp route NOT match "{0}" => "{1}"'.format(route_key, path_str))
        status, headers, body = routes[route_key](req_line, req_headers, req_body)
        return status, headers, body

    def root(self, req_line, headers, body):
        print('App root')
        status = 302
        headers = {
            b'Location': b'/index.html?zoom=17&lat=-21.98046&lon=-47.88036',
        }
        method, path, version = req_line
        body = b"Hello " + method + path + version
        return status, headers, body

    def echo_http(self, req_line, headers, body):
        print('App echo_http')
        method, path, version = req_line
        if method == b'GET':
            texto = b"Hello " + path
        else:
            texto = b"Num entendi"

        staus = 200
        headers = {}
        body = texto
        return staus, headers, body

    def index(self, req_line, headers, body):
        print('App index')
        filename = 'static/index.html'
        return self.file_response(filename)

    def tile(self, req_line, headers, body):
        print('App tile')
        return self.echo_http(req_line, headers, body)

    def static_file(self, req_line, headers, body):
        method, path, version = req_line
        filename = 'static' + path.decode()
        if not os.path.exists(filename):
            print('App Cache miss')
            status = 404
            headers = {}
            body = b'not found'
            return status, headers, body

        return self.file_response(filename)

    def file_response(self, filename):
        status = 200
        headers = {
            b'content-type': self.get_content_type(filename)
        }
        body = b''
        with open(filename, 'br') as file:
            body += file.read()

        return status, headers, body

    def get_content_type(self, filename):
        content_type = b'text/plain; charset=UTF-8'
        if re.match('.*css$', filename):
            content_type = b'text/css; charset=UTF-8'
        if re.match('.*js$', filename):
            content_type = b'application/javascript; charset=UTF-8'
        if re.match('.*ico$', filename):
            content_type = b'image/x-icon; charset=UTF-8'
        if re.match('.*html$', filename):
            content_type = b'text/html; charset=UTF-8'
        print('content_type: {0}\t{1}'.format(content_type.decode(), filename))
        return content_type
