#!/usr/bin/python3
# -*- encoding: utf-8 -*-
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
HTTP_RES_STATUS = {
    200: b'HTTP/1.1 200 OK',
    302: b'HTTP/1.1 302 Found', # Redireciona
    404: b'HTTP/1.1 404 Not Found',
}
