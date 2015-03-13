# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# Originally copied from python-glanceclient

import copy
import hashlib
import httplib
import json
import posixpath
import re
import socket
import StringIO
import struct
import urlparse


import OpenSSL
from oslo_log import log as logging
from six import moves
from tempest_lib import exceptions as lib_exc

from neutron.tests.tempest import exceptions as exc

LOG = logging.getLogger(__name__)
USER_AGENT = 'tempest'
CHUNKSIZE = 1024 * 64  # 64kB
TOKEN_CHARS_RE = re.compile('^[-A-Za-z0-9+/=]*$')


class HTTPClient(object):

    def __init__(self, auth_provider, filters, **kwargs):
        self.auth_provider = auth_provider
        self.filters = filters
        self.endpoint = auth_provider.base_url(filters)
        endpoint_parts = urlparse.urlparse(self.endpoint)
        self.endpoint_scheme = endpoint_parts.scheme
        self.endpoint_hostname = endpoint_parts.hostname
        self.endpoint_port = endpoint_parts.port
        self.endpoint_path = endpoint_parts.path

        self.connection_class = self.get_connection_class(self.endpoint_scheme)
        self.connection_kwargs = self.get_connection_kwargs(
            self.endpoint_scheme, **kwargs)

    @staticmethod
    def get_connection_class(scheme):
        if scheme == 'https':
            return VerifiedHTTPSConnection
        else:
            return httplib.HTTPConnection

    @staticmethod
    def get_connection_kwargs(scheme, **kwargs):
        _kwargs = {'timeout': float(kwargs.get('timeout', 600))}

        if scheme == 'https':
            _kwargs['ca_certs'] = kwargs.get('ca_certs', None)
            _kwargs['cert_file'] = kwargs.get('cert_file', None)
            _kwargs['key_file'] = kwargs.get('key_file', None)
            _kwargs['insecure'] = kwargs.get('insecure', False)
            _kwargs['ssl_compression'] = kwargs.get('ssl_compression', True)

        return _kwargs

    def get_connection(self):
        _class = self.connection_class
        try:
            return _class(self.endpoint_hostname, self.endpoint_port,
                          **self.connection_kwargs)
        except httplib.InvalidURL:
            raise exc.EndpointNotFound

    def _http_request(self, url, method, **kwargs):
        """Send an http request with the specified characteristics.

        Wrapper around httplib.HTTP(S)Connection.request to handle tasks such
        as setting headers and error handling.
        """
        # Copy the kwargs so we can reuse the original in case of redirects
        kwargs['headers'] = copy.deepcopy(kwargs.get('headers', {}))
        kwargs['headers'].setdefault('User-Agent', USER_AGENT)

        self._log_request(method, url, kwargs['headers'])

        conn = self.get_connection()

        try:
            url_parts = urlparse.urlparse(url)
            conn_url = posixpath.normpath(url_parts.path)
            LOG.debug('Actual Path: {path}'.format(path=conn_url))
            if kwargs['headers'].get('Transfer-Encoding') == 'chunked':
                conn.putrequest(method, conn_url)
                for header, value in kwargs['headers'].items():
                    conn.putheader(header, value)
                conn.endheaders()
                chunk = kwargs['body'].read(CHUNKSIZE)
                # Chunk it, baby...
                while chunk:
                    conn.send('%x\r\n%s\r\n' % (len(chunk), chunk))
                    chunk = kwargs['body'].read(CHUNKSIZE)
                conn.send('0\r\n\r\n')
            else:
                conn.request(method, conn_url, **kwargs)
            resp = conn.getresponse()
        except socket.gaierror as e:
            message = ("Error finding address for %(url)s: %(e)s" %
                       {'url': url, 'e': e})
            raise exc.EndpointNotFound(message)
        except (socket.error, socket.timeout) as e:
            message = ("Error communicating with %(endpoint)s %(e)s" %
                       {'endpoint': self.endpoint, 'e': e})
            raise exc.TimeoutException(message)

        body_iter = ResponseBodyIterator(resp)
        # Read body into string if it isn't obviously image data
        if resp.getheader('content-type', None) != 'application/octet-stream':
            body_str = ''.join([body_chunk for body_chunk in body_iter])
            body_iter = StringIO.StringIO(body_str)
            self._log_response(resp, None)
        else:
            self._log_response(resp, body_iter)

        return resp, body_iter

    def _log_request(self, method, url, headers):
        LOG.info('Request: ' + method + ' ' + url)
        if headers:
            headers_out = headers
            if 'X-Auth-Token' in headers and headers['X-Auth-Token']:
                token = headers['X-Auth-Token']
                if len(token) > 64 and TOKEN_CHARS_RE.match(token):
                    headers_out = headers.copy()
                    headers_out['X-Auth-Token'] = "<Token omitted>"
                LOG.info('Request Headers: ' + str(headers_out))

    def _log_response(self, resp, body):
        status = str(resp.status)
        LOG.info("Response Status: " + status)
        if resp.getheaders():
            LOG.info('Response Headers: ' + str(resp.getheaders()))
        if body:
            str_body = str(body)
            length = len(body)
            LOG.info('Response Body: ' + str_body[:2048])
            if length >= 2048:
                self.LOG.debug("Large body (%d) md5 summary: %s", length,
                               hashlib.md5(str_body).hexdigest())

    def json_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type', 'application/json')
        if kwargs['headers']['Content-Type'] != 'application/json':
            msg = "Only application/json content-type is supported."
            raise lib_exc.InvalidContentType(msg)

        if 'body' in kwargs:
            kwargs['body'] = json.dumps(kwargs['body'])

        resp, body_iter = self._http_request(url, method, **kwargs)

        if 'application/json' in resp.getheader('content-type', ''):
            body = ''.join([chunk for chunk in body_iter])
            try:
                body = json.loads(body)
            except ValueError:
                LOG.error('Could not decode response body as JSON')
        else:
            msg = "Only json/application content-type is supported."
            raise lib_exc.InvalidContentType(msg)

        return resp, body

    def raw_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type',
                                     'application/octet-stream')
        if 'body' in kwargs:
            if (hasattr(kwargs['body'], 'read')
                    and method.lower() in ('post', 'put')):
                # We use 'Transfer-Encoding: chunked' because
                # body size may not always be known in advance.
                kwargs['headers']['Transfer-Encoding'] = 'chunked'

        # Decorate the request with auth
        req_url, kwargs['headers'], kwargs['body'] = \
            self.auth_provider.auth_request(
                method=method, url=url, headers=kwargs['headers'],
                body=kwargs.get('body', None), filters=self.filters)
        return self._http_request(req_url, method, **kwargs)


class OpenSSLConnectionDelegator(object):
    """
    An OpenSSL.SSL.Connection delegator.

    Supplies an additional 'makefile' method which httplib requires
    and is not present in OpenSSL.SSL.Connection.

    Note: Since it is not possible to inherit from OpenSSL.SSL.Connection
    a delegator must be used.
    """
    def __init__(self, *args, **kwargs):
        self.connection = OpenSSL.SSL.Connection(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def makefile(self, *args, **kwargs):
        # Ensure the socket is closed when this file is closed
        kwargs['close'] = True
        return socket._fileobject(self.connection, *args, **kwargs)


class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    """
    Extended HTTPSConnection which uses the OpenSSL library
    for enhanced SSL support.
    Note: Much of this functionality can eventually be replaced
          with native Python 3.3 code.
    """
    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 ca_certs=None, timeout=None, insecure=False,
                 ssl_compression=True):
        httplib.HTTPSConnection.__init__(self, host, port,
                                         key_file=key_file,
                                         cert_file=cert_file)
        self.key_file = key_file
        self.cert_file = cert_file
        self.timeout = timeout
        self.insecure = insecure
        self.ssl_compression = ssl_compression
        self.ca_certs = ca_certs
        self.setcontext()

    @staticmethod
    def host_matches_cert(host, x509):
        """
        Verify that the the x509 certificate we have received
        from 'host' correctly identifies the server we are
        connecting to, ie that the certificate's Common Name
        or a Subject Alternative Name matches 'host'.
        """
        # First see if we can match the CN
        if x509.get_subject().commonName == host:
            return True

        # Also try Subject Alternative Names for a match
        san_list = None
        for i in moves.xrange(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if ext.get_short_name() == 'subjectAltName':
                san_list = str(ext)
                for san in ''.join(san_list.split()).split(','):
                    if san == "DNS:%s" % host:
                        return True

        # Server certificate does not match host
        msg = ('Host "%s" does not match x509 certificate contents: '
               'CommonName "%s"' % (host, x509.get_subject().commonName))
        if san_list is not None:
            msg = msg + ', subjectAltName "%s"' % san_list
        raise exc.SSLCertificateError(msg)

    def verify_callback(self, connection, x509, errnum,
                        depth, preverify_ok):
        if x509.has_expired():
            msg = "SSL Certificate expired on '%s'" % x509.get_notAfter()
            raise exc.SSLCertificateError(msg)

        if depth == 0 and preverify_ok is True:
            # We verify that the host matches against the last
            # certificate in the chain
            return self.host_matches_cert(self.host, x509)
        else:
            # Pass through OpenSSL's default result
            return preverify_ok

    def setcontext(self):
        """
        Set up the OpenSSL context.
        """
        self.context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)

        if self.ssl_compression is False:
            self.context.set_options(0x20000)  # SSL_OP_NO_COMPRESSION

        if self.insecure is not True:
            self.context.set_verify(OpenSSL.SSL.VERIFY_PEER,
                                    self.verify_callback)
        else:
            self.context.set_verify(OpenSSL.SSL.VERIFY_NONE,
                                    self.verify_callback)

        if self.cert_file:
            try:
                self.context.use_certificate_file(self.cert_file)
            except Exception as e:
                msg = 'Unable to load cert from "%s" %s' % (self.cert_file, e)
                raise exc.SSLConfigurationError(msg)
            if self.key_file is None:
                # We support having key and cert in same file
                try:
                    self.context.use_privatekey_file(self.cert_file)
                except Exception as e:
                    msg = ('No key file specified and unable to load key '
                           'from "%s" %s' % (self.cert_file, e))
                    raise exc.SSLConfigurationError(msg)

        if self.key_file:
            try:
                self.context.use_privatekey_file(self.key_file)
            except Exception as e:
                msg = 'Unable to load key from "%s" %s' % (self.key_file, e)
                raise exc.SSLConfigurationError(msg)

        if self.ca_certs:
            try:
                self.context.load_verify_locations(self.ca_certs)
            except Exception as e:
                msg = 'Unable to load CA from "%s"' % (self.ca_certs, e)
                raise exc.SSLConfigurationError(msg)
        else:
            self.context.set_default_verify_paths()

    def connect(self):
        """
        Connect to an SSL port using the OpenSSL library and apply
        per-connection parameters.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.timeout is not None:
            # '0' microseconds
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                            struct.pack('LL', self.timeout, 0))
        self.sock = OpenSSLConnectionDelegator(self.context, sock)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            # Remove the reference to the socket but don't close it yet.
            # Response close will close both socket and associated
            # file. Closing socket too soon will cause response
            # reads to fail with socket IO error 'Bad file descriptor'.
            self.sock = None
        httplib.HTTPSConnection.close(self)


class ResponseBodyIterator(object):
    """A class that acts as an iterator over an HTTP response."""

    def __init__(self, resp):
        self.resp = resp

    def __iter__(self):
        while True:
            yield self.next()

    def next(self):
        chunk = self.resp.read(CHUNKSIZE)
        if chunk:
            return chunk
        else:
            raise StopIteration()
