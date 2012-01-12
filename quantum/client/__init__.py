# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Citrix Systems
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
#    @author: Tyler Smith, Cisco Systems

import logging
import httplib
import socket
import urllib

from quantum.common import exceptions
from quantum.common.serializer import Serializer

LOG = logging.getLogger('quantum.client')
EXCEPTIONS = {
    400: exceptions.BadInputError,
    401: exceptions.NotAuthorized,
    420: exceptions.NetworkNotFound,
    421: exceptions.NetworkInUse,
    430: exceptions.PortNotFound,
    431: exceptions.StateInvalid,
    432: exceptions.PortInUseClient,
    440: exceptions.AlreadyAttachedClient}
AUTH_TOKEN_HEADER = "X-Auth-Token"


class ApiCall(object):
    """A Decorator to add support for format and tenant overriding"""
    def __init__(self, function):
        self.function = function

    def __get__(self, instance, owner):
        def with_params(*args, **kwargs):
            """
            Temporarily sets the format and tenant for this request
            """
            (format, tenant) = (instance.format, instance.tenant)

            if 'format' in kwargs:
                instance.format = kwargs['format']
            if 'tenant' in kwargs:
                instance.tenant = kwargs['tenant']

            ret = self.function(instance, *args)
            (instance.format, instance.tenant) = (format, tenant)
            return ret
        return with_params


class Client(object):

    """A base client class - derived from Glance.BaseClient"""

    #Metadata for deserializing xml
    _serialization_metadata = {
        "application/xml": {
            "attributes": {
                "network": ["id", "name"],
                "port": ["id", "state"],
                "attachment": ["id"]},
            "plurals": {"networks": "network",
                        "ports": "port"}},
    }

    # Action query strings
    networks_path = "/networks"
    network_path = "/networks/%s"
    ports_path = "/networks/%s/ports"
    port_path = "/networks/%s/ports/%s"
    attachment_path = "/networks/%s/ports/%s/attachment"

    def __init__(self, host="127.0.0.1", port=9696, use_ssl=False, tenant=None,
                format="xml", testingStub=None, key_file=None, cert_file=None,
                auth_token=None, logger=None,
                action_prefix="/v1.0/tenants/{tenant_id}"):
        """
        Creates a new client to some service.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: True to use SSL, False to use HTTP
        :param tenant: The tenant ID to make requests with
        :param format: The format to query the server with
        :param testingStub: A class that stubs basic server methods for tests
        :param key_file: The SSL key file to use if use_ssl is true
        :param cert_file: The SSL cert file to use if use_ssl is true
        :param auth_token: authentication token to be passed to server
        :param logger: Logger object for the client library
        :param action_prefix: prefix for request URIs
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.tenant = tenant
        self.format = format
        self.connection = None
        self.testingStub = testingStub
        self.key_file = key_file
        self.cert_file = cert_file
        self.logger = logger
        self.auth_token = auth_token
        self.action_prefix = action_prefix

    def get_connection_type(self):
        """
        Returns the proper connection type
        """
        if self.testingStub:
            return self.testingStub
        if self.use_ssl:
            return httplib.HTTPSConnection
        else:
            return httplib.HTTPConnection

    def _send_request(self, conn, method, action, body, headers):
        # Salvatore: Isolating this piece of code in its own method to
        # facilitate stubout for testing
        if self.logger:
            self.logger.debug("Quantum Client Request:\n" \
                    + method + " " + action + "\n")
            if body:
                self.logger.debug(body)
        conn.request(method, action, body, headers)
        return conn.getresponse()

    def do_request(self, method, action, body=None,
                   headers=None, params=None, exception_args={}):
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
        LOG.debug("Client issuing request: %s", action)
        # Ensure we have a tenant id
        if not self.tenant:
            raise Exception("Tenant ID not set")

        # Add format and tenant_id
        action += ".%s" % self.format
        action = self.action_prefix + action
        action = action.replace('{tenant_id}', self.tenant)

        if isinstance(params, dict):
            action += '?' + urllib.urlencode(params)
        if body:
            body = self.serialize(body)

        try:
            connection_type = self.get_connection_type()
            headers = headers or {"Content-Type":
                                      "application/%s" % self.format}
            # if available, add authentication token
            if self.auth_token:
                headers[AUTH_TOKEN_HEADER] = self.auth_token
            # Open connection and send request, handling SSL certs
            certs = {'key_file': self.key_file, 'cert_file': self.cert_file}
            certs = dict((x, certs[x]) for x in certs if certs[x] is not None)

            if self.use_ssl and len(certs):
                conn = connection_type(self.host, self.port, **certs)
            else:
                conn = connection_type(self.host, self.port)
            res = self._send_request(conn, method, action, body, headers)
            status_code = self.get_status_code(res)
            data = res.read()

            if self.logger:
                self.logger.debug("Quantum Client Reply (code = %s) :\n %s" \
                        % (str(status_code), data))
            if status_code in (httplib.OK,
                               httplib.CREATED,
                               httplib.ACCEPTED,
                               httplib.NO_CONTENT):
                return self.deserialize(data, status_code)
            else:
                error_message = res.read()
                LOG.debug("Server returned error: %s", status_code)
                LOG.debug("Error message: %s", error_message)
                # Create exception with HTTP status code and message
                if res.status in EXCEPTIONS:
                    raise EXCEPTIONS[res.status](**exception_args)
                # Add error code and message to exception arguments
                ex = Exception("Server returned error: %s" % status_code)
                ex.args = ([dict(status_code=status_code,
                                 message=error_message)],)
                raise ex
        except (socket.error, IOError), e:
            msg = "Unable to connect to server. Got error: %s" % e
            LOG.exception(msg)
            raise Exception(msg)

    def get_status_code(self, response):
        """
        Returns the integer status code from the response, which
        can be either a Webob.Response (used in testing) or httplib.Response
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status

    def serialize(self, data):
        """
        Serializes a dictionary with a single key (which can contain any
        structure) into either xml or json
        """
        if data is None:
            return None
        elif isinstance(data, dict):
            return Serializer().serialize(data, self.content_type())
        else:
            raise Exception("unable to serialize object of type = '%s'" \
                                % type(data))

    def deserialize(self, data, status_code):
        """
        Deserializes a an xml or json string into a dictionary
        """
        if status_code == 204:
            return data
        return Serializer(self._serialization_metadata).\
                    deserialize(data, self.content_type())

    def content_type(self, format=None):
        """
        Returns the mime-type for either 'xml' or 'json'.  Defaults to the
        currently set format
        """
        if not format:
            format = self.format
        return "application/%s" % (format)

    @ApiCall
    def list_networks(self):
        """
        Fetches a list of all networks for a tenant
        """
        return self.do_request("GET", self.networks_path)

    @ApiCall
    def show_network_details(self, network):
        """
        Fetches the details of a certain network
        """
        return self.do_request("GET", self.network_path % (network),
                                        exception_args={"net_id": network})

    @ApiCall
    def create_network(self, body=None):
        """
        Creates a new network
        """
        return self.do_request("POST", self.networks_path, body=body)

    @ApiCall
    def update_network(self, network, body=None):
        """
        Updates a network
        """
        return self.do_request("PUT", self.network_path % (network), body=body,
                                        exception_args={"net_id": network})

    @ApiCall
    def delete_network(self, network):
        """
        Deletes the specified network
        """
        return self.do_request("DELETE", self.network_path % (network),
                                        exception_args={"net_id": network})

    @ApiCall
    def list_ports(self, network):
        """
        Fetches a list of ports on a given network
        """
        return self.do_request("GET", self.ports_path % (network))

    @ApiCall
    def show_port_details(self, network, port):
        """
        Fetches the details of a certain port
        """
        return self.do_request("GET", self.port_path % (network, port),
                       exception_args={"net_id": network, "port_id": port})

    @ApiCall
    def create_port(self, network, body=None):
        """
        Creates a new port on a given network
        """
        return self.do_request("POST", self.ports_path % (network), body=body,
                       exception_args={"net_id": network})

    @ApiCall
    def delete_port(self, network, port):
        """
        Deletes the specified port from a network
        """
        return self.do_request("DELETE", self.port_path % (network, port),
                       exception_args={"net_id": network, "port_id": port})

    @ApiCall
    def update_port(self, network, port, body=None):
        """
        Sets the attributes of the specified port
        """
        return self.do_request("PUT",
            self.port_path % (network, port), body=body,
                       exception_args={"net_id": network,
                                       "port_id": port})

    @ApiCall
    def show_port_attachment(self, network, port):
        """
        Fetches the attachment-id associated with the specified port
        """
        return self.do_request("GET", self.attachment_path % (network, port),
                       exception_args={"net_id": network, "port_id": port})

    @ApiCall
    def attach_resource(self, network, port, body=None):
        """
        Sets the attachment-id of the specified port
        """
        return self.do_request("PUT",
            self.attachment_path % (network, port), body=body,
                       exception_args={"net_id": network,
                                       "port_id": port,
                                       "attach_id": str(body)})

    @ApiCall
    def detach_resource(self, network, port):
        """
        Removes the attachment-id of the specified port
        """
        return self.do_request("DELETE",
                               self.attachment_path % (network, port),
                    exception_args={"net_id": network, "port_id": port})
