#!/usr/bin/env python3
"""Simple server written using an event loop."""

import argparse
import email.message
import json
import logging
import os
import sys
try:
    import ssl
except ImportError:  # pragma: no cover
    ssl = None

assert sys.version >= '3.3', 'Please use Python 3.3 or higher.'

from asyncio import coroutine, get_event_loop, set_event_loop
from aiohttp import client, Response, HttpErrorException
from aiohttp.server import ServerHttpProtocol
from pprint import pformat


log = logging.getLogger(__name__)


def send_notify(url, secret):
    """Sends a notification packet to url that a message is waiting with given
    secret."""
    # TODO Store the notification in the database
    notify = {'type': 'notify',
              'callback' : 'http://{}:{}/pickup'.format(args.host, args.port),
              'secret': secret}
    notify_data = json.dumps(notify).encode('utf-8')
    response = yield from client.request(method='POST',
                                         url=url,
                                         data=notify_data)
    report_data = yield from response.read()
    report = json.loads(report_data.decode('utf-8'))
    log.debug('send_notify: report {}'.format(report))
    return report


def recv_notify(data):
    """Received a notification packet, respond with a pickup."""
    notify_data = yield from data.read()
    notify = json.loads(notify_data.decode('utf-8'))
    messages = yield from send_pickup(notify)
    log.debug('recv_notify: returned messages {}'.format(messages))
    # TODO Import messages into database
    report = [['xchan', 'posted', 'receiver']]
    report_data = json.dumps(report).encode('utf-8')
    return report_data


def send_pickup(notify):
    """Send a pickup request using the secret from the notification.
    The response is the actual message."""
    url = notify.get('callback', None)
    secret = notify.get('secret', None)
    log.debug('send_pickup: secret {} callback {}'.format(secret, url))
    pickup = {'type': 'pickup',
              'secret': secret}
    pickup_data = json.dumps(pickup).encode('utf-8')
    response = yield from client.request(method='POST',
                                         url=url,
                                         data=pickup_data)
    message_data = yield from response.read()
    messages = json.loads(message_data.decode('utf-8'))
    log.debug('send_pickup: messages {}'.format(messages))
    return messages


def recv_pickup(data):
    """Received a pickup request to deliver a message for given secret."""
    pickup_data = yield from data.read()
    pickup = json.loads(pickup_data.decode('utf-8'))
    secret = pickup.get('secret', None)
    log.debug('recv_pickup: pickup for secret {}'.format(secret))
    # TODO Read message from database associated with secret
    message = {'message_id': 'sdfger124124',
               'body': 'Message!',
               'author': 'author'}
    # TODO Read original notify from database associated with secret
    notify = {'type': 'notify',
              'secret': secret}
    messages_pickup = []
    messages_pickup.append({'notify': notify,
                            'message': message})
    messages = {'pickup': messages_pickup}
    message_data = json.dumps(messages).encode('utf-8')
    return message_data


class HttpServer(ServerHttpProtocol):

    @coroutine
    def handle_request(self, message, payload):
        print('method = {!r}; path = {!r}; version = {!r}'.format(
            message.method, message.path, message.version))

        path = message.path

        if path == '/comment':
            log.debug('handle_request: comment')
            # TODO Read message from request and store it with a secret
            secret = '3452345e23'
            # TODO Determine url from recipient
            url = 'http://{}:{}/notify'.format(args.host, args.port)
            response = Response(self.transport, 200)
            response.add_header('Transfer-Encoding', 'chunked')
            response.add_header('Content-type', 'text/html; charset=utf-8')
            response.add_chunking_filter(1025)
            response.send_headers()
            response.write(b'<html><body><p>ok</p></body></html>')
            #response.write(json.dumps(report).encode('utf-8'))
            response.write_eof()
            if response.keep_alive():
                self.keep_alive(True)
            # TODO How does one make the response independent of the
            # notification chain? 
            report = yield from send_notify(url, secret)
            log.debug('handle_request: data after comment {}'.format(report))
            return
        elif path == '/notify':
            log.debug('handle_request: notify')
            report_data = yield from recv_notify(payload)
            response = Response(self.transport, 200)
            response.add_header('Transfer-Encoding', 'chunked')
            response.add_header('Content-type', 'application/json; charset=utf-8')
            response.add_chunking_filter(1025)
            response.send_headers()
            response.write(report_data)
            response.write_eof()
            #if response.keep_alive():
            #    self.keep_alive(True)
            return
        elif path == '/pickup':
            log.debug('handle_request: pickup')
            message_data = yield from recv_pickup(payload)
            response = Response(self.transport, 200)
            response.add_header('Transfer-Encoding', 'chunked')
            response.add_header('Content-type', 'application/json; charset=utf-8')
            response.add_chunking_filter(1025)
            response.send_headers()
            response.write(message_data)
            response.write_eof()
            #if response.keep_alive():
            #    self.keep_alive(True)
            return


        if (not (path.isprintable() and path.startswith('/')) or '/.' in path):
            print('bad path', repr(path))
            path = None
        else:
            path = '.' + path
            if not os.path.exists(path):
                print('no file', repr(path))
                path = None
            else:
                isdir = os.path.isdir(path)

        if not path:
            raise HttpErrorException(404)

        headers = email.message.Message()
        for hdr, val in message.headers:
            print(hdr, val)
            headers.add_header(hdr, val)

        if isdir and not path.endswith('/'):
            path = path + '/'
            raise HttpErrorException(
                302, headers=(('URI', path), ('Location', path)))

        response = Response(self.transport, 200)
        response.add_header('Transfer-Encoding', 'chunked')

        # content encoding
        accept_encoding = headers.get('accept-encoding', '').lower()
        if 'deflate' in accept_encoding:
            response.add_header('Content-Encoding', 'deflate')
            response.add_compression_filter('deflate')
        elif 'gzip' in accept_encoding:
            response.add_header('Content-Encoding', 'gzip')
            response.add_compression_filter('gzip')

        response.add_chunking_filter(1025)

        if isdir:
            response.add_header('Content-type', 'text/html')
            response.send_headers()

            response.write(b'<ul>\r\n')
            for name in sorted(os.listdir(path)):
                if name.isprintable() and not name.startswith('.'):
                    try:
                        bname = name.encode('ascii')
                    except UnicodeError:
                        pass
                    else:
                        if os.path.isdir(os.path.join(path, name)):
                            response.write(b'<li><a href="' + bname +
                                           b'/">' + bname + b'/</a></li>\r\n')
                        else:
                            response.write(b'<li><a href="' + bname +
                                           b'">' + bname + b'</a></li>\r\n')
            response.write(b'</ul>')
        else:
            response.add_header('Content-type', 'text/plain')
            response.send_headers()

            try:
                with open(path, 'rb') as fp:
                    chunk = fp.read(8196)
                    while chunk:
                        response.write(chunk)
                        chunk = fp.read(8196)
            except OSError:
                response.write(b'Cannot open')

        response.write_eof()
        if response.keep_alive():
            self.keep_alive(True)


ARGS = argparse.ArgumentParser(description="Run simple http server.")
ARGS.add_argument(
    '--host', action="store", dest='host',
    default='127.0.0.1', help='Host name')
ARGS.add_argument(
    '--port', action="store", dest='port',
    default=8080, type=int, help='Port number')
ARGS.add_argument(
    '--iocp', action="store_true", dest='iocp', help='Windows IOCP event loop')
ARGS.add_argument(
    '--ssl', action="store_true", dest='ssl', help='Run ssl mode.')
ARGS.add_argument(
    '--sslcert', action="store", dest='certfile', help='SSL cert file.')
ARGS.add_argument(
    '--sslkey', action="store", dest='keyfile', help='SSL key file.')


def main():
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(console)
    log.setLevel(logging.DEBUG)
    log.propagate = False
    #logging.root.addHandler(console)
    #logging.root.setLevel(logging.DEBUG)
    #logging.root.propagate = False

    # FIXME moved to __main__
    # Should create global config
    #args = ARGS.parse_args()

    if ':' in args.host:
        args.host, port = args.host.split(':', 1)
        args.port = int(port)

    if args.iocp:
        from asyncio import windows_events
        sys.argv.remove('--iocp')
        log.info('using iocp')
        el = windows_events.ProactorEventLoop()
        set_event_loop(el)

    if args.ssl:
        here = os.path.join(os.path.dirname(__file__), 'tests')

        if args.certfile:
            certfile = args.certfile or os.path.join(here, 'sample.crt')
            keyfile = args.keyfile or os.path.join(here, 'sample.key')
        else:
            certfile = os.path.join(here, 'sample.crt')
            keyfile = os.path.join(here, 'sample.key')

        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        sslcontext.load_cert_chain(certfile, keyfile)
    else:
        sslcontext = None

    loop = get_event_loop()
    f = loop.create_server(
        lambda: HttpServer(debug=True, keep_alive=75), args.host, args.port,
        ssl=sslcontext)
    svr = loop.run_until_complete(f)
    socks = svr.sockets
    print('serving on', socks[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    args = ARGS.parse_args()
    main()
