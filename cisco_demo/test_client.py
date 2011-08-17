"""A base client class - derived from Quantum.MiniClient"""

import httplib
import socket
import urllib


class ExtClient(object):

    action_prefix = '/v0.1/extensions/csco/tenants/{tenant_id}'
    #action_prefix = '/v0.1/tenants/{tenant_id}'
    def __init__(self, host, port, use_ssl):
        """
        Creates a new client to some service.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: Should we use HTTPS?
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.connection = None

    def get_connection_type(self):
        """
        Returns the proper connection type
        """
        if self.use_ssl:
            return httplib.HTTPSConnection
        else:
            return httplib.HTTPConnection

    def do_request(self, tenant, method, action, body=None,
                   headers=None, params=None):
        """
        Connects to the server and issues a request.  
        Returns the result data, or raises an appropriate exception if
        HTTP status code is not 2xx

        :param method: HTTP method ("GET", "POST", "PUT", etc...)
        :param body: string of data to send, or None (default)
        :param headers: mapping of key/value pairs to add as headers
        :param params: dictionary of key/value pairs to add to append
                             to action

        """
        action = ExtClient.action_prefix + action
        action = action.replace('{tenant_id}', tenant)
        if type(params) is dict:
            action += '?' + urllib.urlencode(params)

        try:
            connection_type = self.get_connection_type()
            headers = headers or {}
            
            # Open connection and send request
            c = connection_type(self.host, self.port)
            c.request(method, action, body, headers)
            res = c.getresponse()
            status_code = self.get_status_code(res)
            if status_code in (httplib.OK,
                               httplib.CREATED,
                               httplib.ACCEPTED,
                               httplib.NO_CONTENT):
                return res
            else:
                raise Exception("Server returned error: %s" % res.read())

        except (socket.error, IOError), e:
            raise Exception("Unable to connect to "
                            "server. Got error: %s" % e)

    def get_status_code(self, response):
        """
        Returns the integer status code from the response, which
        can be either a Webob.Response (used in testing) or httplib.Response
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status
        
