#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, random, sys, requests

from socketserver import ThreadingMixIn
import threading
import re

authorization = {
    "default": "Bearer secret-token:supersecret",
    "konsum": "Bearer secret-token:supersecret"
}
authorization_lite = {
    "default": "Bearer secret-token:hello",
    "konsum": "Bearer secret-token:hello"
}

def check_auth(path, headers, method):
    match = re.match("/instances/([a-zA-Z0-9_]+)/private/orders(/[-a-zA-Z0-9_.]+)?", path)
    if match:
        instance = match[1]
        order = match[2]
        
        print("checking auth: '%s' request for instance=%s and order %s" % (method, instance, order))

        if (method == 'get' and order is not None) or (method in ['post', 'delete'] and order is None):
            try:
                print("\trequest is elegible")
                actual_auth = headers['authorization']
                replace_auth = authorization[instance]
                needed_auth = authorization_lite[instance]

                print("\tchecking")

                if actual_auth == needed_auth:
                    return (True, {'authorization': replace_auth})
            except:
                pass
        return (False, {})
    else:
        return (False, {})

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)
        return

    def do_OPTIONS(self, body=True):
        try:
            req_header = self.parse_headers()
            url = 'https://{}{}'.format(hostname, self.path)
            resp = requests.options(url, headers=req_header, verify=False)

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
        except:
            self.send_error(502, 'Internetkurort Bad Gateway')
        
        
    def do_GET(self, body=True):
        try:
            req_header = self.parse_headers()
            allow, new_headers = check_auth(self.path, req_header, 'get')

            if allow:
                url = 'https://{}{}'.format(hostname, self.path)
                resp = requests.get(url, headers=(req_header | new_headers), verify=False)

                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                msg = resp.text
                if body:
                    self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
            else:
                self.send_error(401, 'Unauthenticated')
        except:
            self.send_error(502, 'Internetkurort Bad Gateway')

    def do_DELETE(self, body=True):
        try:
            req_header = self.parse_headers()
            allow, new_headers = check_auth(self.path, req_header, 'delete')

            if allow:
                url = 'https://{}{}'.format(hostname, self.path)
                resp = requests.delete(url, headers=(req_header | new_headers), verify=False)

                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                msg = resp.text
                if body:
                    self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
            else:
                self.send_error(401, 'Unauthenticated')
        except:
            self.send_error(502, 'Internetkurort Bad Gateway')

    def do_POST(self, body=True):
        try:
            req_header = self.parse_headers()
            allow, new_headers = check_auth(self.path, req_header, 'post')

            if allow:
                url = 'https://{}{}'.format(hostname, self.path)
                print("content len")
                content_len = 0
                try:
                    content_len = int(req_header['content-length'])
                except:
                    content_len = 0
                print("content len", content_len)
                post_body = self.rfile.read(content_len)
                resp = requests.post(url, data=post_body, headers=(req_header | new_headers), verify=False)
                print("send")
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                if body:
                    self.wfile.write(resp.content)
            else:
                self.send_error(401, 'Unauthenticated')
        except:
            self.send_error(502, 'Internetkurort Bad Gateway')

    def parse_headers(self):
        return {a.lower():b for (a,b) in self.headers.items() if a.lower() not in ['host']}

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        for key in respheaders:
            if key.lower() not in ['content-encoding', 'transfer-encoding', 'content-length']:
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=9999,
                        help='serve HTTP requests on specified port (default: random)')
    parser.add_argument('--hostname', dest='hostname', type=str, default='en.wikipedia.org',
                        help='hostname to be processd (default: en.wikipedia.org)')
    args = parser.parse_args(argv)
    return args

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main(argv=sys.argv[1:]):
    global hostname
    args = parse_args(argv)
    hostname = args.hostname
    print('http server is starting on {} port {}...'.format(args.hostname, args.port))
    server_address = ('127.0.0.1', args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()

if __name__ == '__main__':
    main()
