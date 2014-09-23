# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2014 Big Switch Networks, Inc.
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
#
# @author: Mandeep Dhami, Big Switch Networks, Inc.
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.
# @author: Kevin Benton, Big Switch Networks, Inc.

"""
This module manages the HTTP and HTTPS connections to the backend controllers.

The main class it provides for external use is ServerPool which manages a set
of ServerProxy objects that correspond to individual backend controllers.

The following functionality is handled by this module:
- Translation of rest_* function calls to HTTP/HTTPS calls to the controllers
- Automatic failover between controllers
- SSL Certificate enforcement
- HTTP Authentication

"""
import base64
import httplib
import json
import os
import socket
import ssl
import time
import weakref

import eventlet
import eventlet.corolocal
from oslo.config import cfg

from neutron.common import exceptions
from neutron.common import utils
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.bigswitch.db import consistency_db as cdb

LOG = logging.getLogger(__name__)

# The following are used to invoke the API on the external controller
CAPABILITIES_PATH = "/capabilities"
NET_RESOURCE_PATH = "/tenants/%s/networks"
PORT_RESOURCE_PATH = "/tenants/%s/networks/%s/ports"
ROUTER_RESOURCE_PATH = "/tenants/%s/routers"
ROUTER_INTF_OP_PATH = "/tenants/%s/routers/%s/interfaces"
NETWORKS_PATH = "/tenants/%s/networks/%s"
FLOATINGIPS_PATH = "/tenants/%s/floatingips/%s"
PORTS_PATH = "/tenants/%s/networks/%s/ports/%s"
ATTACHMENT_PATH = "/tenants/%s/networks/%s/ports/%s/attachment"
ROUTERS_PATH = "/tenants/%s/routers/%s"
ROUTER_INTF_PATH = "/tenants/%s/routers/%s/interfaces/%s"
TOPOLOGY_PATH = "/topology"
HEALTH_PATH = "/health"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
BASE_URI = '/networkService/v1.1'
ORCHESTRATION_SERVICE_ID = 'Neutron v2.0'
HASH_MATCH_HEADER = 'X-BSN-BVS-HASH-MATCH'
REQ_CONTEXT_HEADER = 'X-REQ-CONTEXT'
# error messages
NXNETWORK = 'NXVNS'
HTTP_SERVICE_UNAVAILABLE_RETRY_COUNT = 3
HTTP_SERVICE_UNAVAILABLE_RETRY_INTERVAL = 3


class RemoteRestError(exceptions.NeutronException):
    message = _("Error in REST call to remote network "
                "controller: %(reason)s")
    status = None

    def __init__(self, **kwargs):
        self.status = kwargs.pop('status', None)
        self.reason = kwargs.get('reason')
        super(RemoteRestError, self).__init__(**kwargs)


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, neutron_id, timeout,
                 base_uri, name, mypool, combined_cert):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = SUCCESS_CODES
        self.auth = None
        self.neutron_id = neutron_id
        self.failed = False
        self.capabilities = []
        # enable server to reference parent pool
        self.mypool = mypool
        # cache connection here to avoid a SSL handshake for every connection
        self.currentconn = None
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()
        self.combined_cert = combined_cert

    def get_capabilities(self):
        try:
            body = self.rest_call('GET', CAPABILITIES_PATH)[2]
            self.capabilities = json.loads(body)
        except Exception:
            LOG.exception(_("Couldn't retrieve capabilities. "
                            "Newer API calls won't be supported."))
        LOG.info(_("The following capabilities were received "
                   "for %(server)s: %(cap)s"), {'server': self.server,
                                                'cap': self.capabilities})
        return self.capabilities

    def rest_call(self, action, resource, data='', headers=None,
                  timeout=False, reconnect=False, hash_handler=None):
        uri = self.base_uri + resource
        body = json.dumps(data)
        headers = headers or {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['NeutronProxy-Agent'] = self.name
        headers['Instance-ID'] = self.neutron_id
        headers['Orchestration-Service-ID'] = ORCHESTRATION_SERVICE_ID
        if hash_handler:
            # this will be excluded on calls that don't need hashes
            # (e.g. topology sync, capability checks)
            headers[HASH_MATCH_HEADER] = hash_handler.read_for_update()
        else:
            hash_handler = cdb.HashHandler()
        if 'keep-alive' in self.capabilities:
            headers['Connection'] = 'keep-alive'
        else:
            reconnect = True
        if self.auth:
            headers['Authorization'] = self.auth

        LOG.debug(_("ServerProxy: server=%(server)s, port=%(port)d, "
                    "ssl=%(ssl)r"),
                  {'server': self.server, 'port': self.port, 'ssl': self.ssl})
        LOG.debug(_("ServerProxy: resource=%(resource)s, data=%(data)r, "
                    "headers=%(headers)r, action=%(action)s"),
                  {'resource': resource, 'data': data, 'headers': headers,
                   'action': action})

        # unspecified timeout is False because a timeout can be specified as
        # None to indicate no timeout.
        if timeout is False:
            timeout = self.timeout

        if timeout != self.timeout:
            # need a new connection if timeout has changed
            reconnect = True

        if not self.currentconn or reconnect:
            if self.currentconn:
                self.currentconn.close()
            if self.ssl:
                self.currentconn = HTTPSConnectionWithValidation(
                    self.server, self.port, timeout=timeout)
                if self.currentconn is None:
                    LOG.error(_('ServerProxy: Could not establish HTTPS '
                                'connection'))
                    return 0, None, None, None
                self.currentconn.combined_cert = self.combined_cert
            else:
                self.currentconn = httplib.HTTPConnection(
                    self.server, self.port, timeout=timeout)
                if self.currentconn is None:
                    LOG.error(_('ServerProxy: Could not establish HTTP '
                                'connection'))
                    return 0, None, None, None

        try:
            self.currentconn.request(action, uri, body, headers)
            response = self.currentconn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                hash_value = response.getheader(HASH_MATCH_HEADER)
                # don't clear hash from DB if a hash header wasn't present
                if hash_value is not None:
                    hash_handler.put_hash(hash_value)
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except httplib.HTTPException:
            # If we were using a cached connection, try again with a new one.
            with excutils.save_and_reraise_exception() as ctxt:
                self.currentconn.close()
                if reconnect:
                    # if reconnect is true, this was on a fresh connection so
                    # reraise since this server seems to be broken
                    ctxt.reraise = True
                else:
                    # if reconnect is false, it was a cached connection so
                    # try one more time before re-raising
                    ctxt.reraise = False
            return self.rest_call(action, resource, data, headers,
                                  timeout=timeout, reconnect=True)
        except (socket.timeout, socket.error) as e:
            self.currentconn.close()
            LOG.error(_('ServerProxy: %(action)s failure, %(e)r'),
                      {'action': action, 'e': e})
            ret = 0, None, None, None
        LOG.debug(_("ServerProxy: status=%(status)d, reason=%(reason)r, "
                    "ret=%(ret)s, data=%(data)r"), {'status': ret[0],
                                                    'reason': ret[1],
                                                    'ret': ret[2],
                                                    'data': ret[3]})
        return ret


class ServerPool(object):

    def __init__(self, timeout=False,
                 base_uri=BASE_URI, name='NeutronRestProxy'):
        LOG.debug(_("ServerPool: initializing"))
        # 'servers' is the list of network controller REST end-points
        # (used in order specified till one succeeds, and it is sticky
        # till next failure). Use 'server_auth' to encode api-key
        servers = cfg.CONF.RESTPROXY.servers
        self.auth = cfg.CONF.RESTPROXY.server_auth
        self.ssl = cfg.CONF.RESTPROXY.server_ssl
        self.neutron_id = cfg.CONF.RESTPROXY.neutron_id
        self.base_uri = base_uri
        self.name = name
        self.contexts = {}
        self.timeout = cfg.CONF.RESTPROXY.server_timeout
        self.always_reconnect = not cfg.CONF.RESTPROXY.cache_connections
        default_port = 8000
        if timeout is not False:
            self.timeout = timeout

        # Function to use to retrieve topology for consistency syncs.
        # Needs to be set by module that uses the servermanager.
        self.get_topo_function = None
        self.get_topo_function_args = {}

        if not servers:
            raise cfg.Error(_('Servers not defined. Aborting server manager.'))
        servers = [s if len(s.rsplit(':', 1)) == 2
                   else "%s:%d" % (s, default_port)
                   for s in servers]
        if any((len(spl) != 2 or not spl[1].isdigit())
               for spl in [sp.rsplit(':', 1)
                           for sp in servers]):
            raise cfg.Error(_('Servers must be defined as <ip>:<port>. '
                              'Configuration was %s') % servers)
        self.servers = [
            self.server_proxy_for(server, int(port))
            for server, port in (s.rsplit(':', 1) for s in servers)
        ]
        eventlet.spawn(self._consistency_watchdog,
                       cfg.CONF.RESTPROXY.consistency_interval)
        LOG.debug(_("ServerPool: initialization done"))

    def set_context(self, context):
        # this context needs to be local to the greenthread
        # so concurrent requests don't use the wrong context.
        # Use a weakref so the context is garbage collected
        # after the plugin is done with it.
        ref = weakref.ref(context)
        self.contexts[eventlet.corolocal.get_ident()] = ref

    def get_context_ref(self):
        # Try to get the context cached for this thread. If one
        # doesn't exist or if it's been garbage collected, this will
        # just return None.
        try:
            return self.contexts[eventlet.corolocal.get_ident()]()
        except KeyError:
            return None

    def get_capabilities(self):
        # lookup on first try
        try:
            return self.capabilities
        except AttributeError:
            # each server should return a list of capabilities it supports
            # e.g. ['floatingip']
            capabilities = [set(server.get_capabilities())
                            for server in self.servers]
            # Pool only supports what all of the servers support
            self.capabilities = set.intersection(*capabilities)
            return self.capabilities

    def server_proxy_for(self, server, port):
        combined_cert = self._get_combined_cert_for_server(server, port)
        return ServerProxy(server, port, self.ssl, self.auth, self.neutron_id,
                           self.timeout, self.base_uri, self.name, mypool=self,
                           combined_cert=combined_cert)

    def _get_combined_cert_for_server(self, server, port):
        # The ssl library requires a combined file with all trusted certs
        # so we make one containing the trusted CAs and the corresponding
        # host cert for this server
        combined_cert = None
        if self.ssl and not cfg.CONF.RESTPROXY.no_ssl_validation:
            base_ssl = cfg.CONF.RESTPROXY.ssl_cert_directory
            host_dir = os.path.join(base_ssl, 'host_certs')
            ca_dir = os.path.join(base_ssl, 'ca_certs')
            combined_dir = os.path.join(base_ssl, 'combined')
            combined_cert = os.path.join(combined_dir, '%s.pem' % server)
            if not os.path.exists(base_ssl):
                raise cfg.Error(_('ssl_cert_directory [%s] does not exist. '
                                  'Create it or disable ssl.') % base_ssl)
            for automake in [combined_dir, ca_dir, host_dir]:
                if not os.path.exists(automake):
                    os.makedirs(automake)

            # get all CA certs
            certs = self._get_ca_cert_paths(ca_dir)

            # check for a host specific cert
            hcert, exists = self._get_host_cert_path(host_dir, server)
            if exists:
                certs.append(hcert)
            elif cfg.CONF.RESTPROXY.ssl_sticky:
                self._fetch_and_store_cert(server, port, hcert)
                certs.append(hcert)
            if not certs:
                raise cfg.Error(_('No certificates were found to verify '
                                  'controller %s') % (server))
            self._combine_certs_to_file(certs, combined_cert)
        return combined_cert

    def _combine_certs_to_file(self, certs, cfile):
        '''
        Concatenates the contents of each certificate in a list of
        certificate paths to one combined location for use with ssl
        sockets.
        '''
        with open(cfile, 'w') as combined:
            for c in certs:
                with open(c, 'r') as cert_handle:
                    combined.write(cert_handle.read())

    def _get_host_cert_path(self, host_dir, server):
        '''
        returns full path and boolean indicating existence
        '''
        hcert = os.path.join(host_dir, '%s.pem' % server)
        if os.path.exists(hcert):
            return hcert, True
        return hcert, False

    def _get_ca_cert_paths(self, ca_dir):
        certs = [os.path.join(root, name)
                 for name in [
                     name for (root, dirs, files) in os.walk(ca_dir)
                     for name in files
                 ]
                 if name.endswith('.pem')]
        return certs

    def _fetch_and_store_cert(self, server, port, path):
        '''
        Grabs a certificate from a server and writes it to
        a given path.
        '''
        try:
            cert = ssl.get_server_certificate((server, port))
        except Exception as e:
            raise cfg.Error(_('Could not retrieve initial '
                              'certificate from controller %(server)s. '
                              'Error details: %(error)s') %
                            {'server': server, 'error': str(e)})

        LOG.warning(_("Storing to certificate for host %(server)s "
                      "at %(path)s") % {'server': server,
                                        'path': path})
        self._file_put_contents(path, cert)

        return cert

    def _file_put_contents(self, path, contents):
        # Simple method to write to file.
        # Created for easy Mocking
        with open(path, 'w') as handle:
            handle.write(contents)

    def server_failure(self, resp, ignore_codes=[]):
        """Define failure codes as required.

        Note: We assume 301-303 is a failure, and try the next server in
        the server pool.
        """
        return (resp[0] in FAILURE_CODES and resp[0] not in ignore_codes)

    def action_success(self, resp):
        """Defining success codes as required.

        Note: We assume any valid 2xx as being successful response.
        """
        return resp[0] in SUCCESS_CODES

    @utils.synchronized('bsn-rest-call')
    def rest_call(self, action, resource, data, headers, ignore_codes,
                  timeout=False):
        context = self.get_context_ref()
        if context:
            # include the requesting context information if available
            cdict = context.to_dict()
            headers[REQ_CONTEXT_HEADER] = json.dumps(cdict)
        hash_handler = cdb.HashHandler(context=context)
        good_first = sorted(self.servers, key=lambda x: x.failed)
        first_response = None
        for active_server in good_first:
            for x in range(HTTP_SERVICE_UNAVAILABLE_RETRY_COUNT + 1):
                ret = active_server.rest_call(action, resource, data, headers,
                                              timeout,
                                              reconnect=self.always_reconnect,
                                              hash_handler=hash_handler)
                if ret[0] != httplib.SERVICE_UNAVAILABLE:
                    break
                time.sleep(HTTP_SERVICE_UNAVAILABLE_RETRY_INTERVAL)

            # If inconsistent, do a full synchronization
            if ret[0] == httplib.CONFLICT:
                if not self.get_topo_function:
                    raise cfg.Error(_('Server requires synchronization, '
                                      'but no topology function was defined.'))
                # The hash was incorrect so it needs to be removed
                hash_handler.put_hash('')
                data = self.get_topo_function(**self.get_topo_function_args)
                active_server.rest_call('PUT', TOPOLOGY_PATH, data,
                                        timeout=None)
            # Store the first response as the error to be bubbled up to the
            # user since it was a good server. Subsequent servers will most
            # likely be cluster slaves and won't have a useful error for the
            # user (e.g. 302 redirect to master)
            if not first_response:
                first_response = ret
            if not self.server_failure(ret, ignore_codes):
                active_server.failed = False
                return ret
            else:
                LOG.error(_('ServerProxy: %(action)s failure for servers: '
                            '%(server)r Response: %(response)s'),
                          {'action': action,
                           'server': (active_server.server,
                                      active_server.port),
                           'response': ret[3]})
                LOG.error(_("ServerProxy: Error details: status=%(status)d, "
                            "reason=%(reason)r, ret=%(ret)s, data=%(data)r"),
                          {'status': ret[0], 'reason': ret[1], 'ret': ret[2],
                           'data': ret[3]})
                active_server.failed = True

        # All servers failed, reset server list and try again next time
        LOG.error(_('ServerProxy: %(action)s failure for all servers: '
                    '%(server)r'),
                  {'action': action,
                   'server': tuple((s.server,
                                    s.port) for s in self.servers)})
        return first_response

    def rest_action(self, action, resource, data='', errstr='%s',
                    ignore_codes=None, headers=None, timeout=False):
        """
        Wrapper for rest_call that verifies success and raises a
        RemoteRestError on failure with a provided error string
        By default, 404 errors on DELETE calls are ignored because
        they already do not exist on the backend.
        """
        ignore_codes = ignore_codes or []
        headers = headers or {}
        if not ignore_codes and action == 'DELETE':
            ignore_codes = [404]
        resp = self.rest_call(action, resource, data, headers, ignore_codes,
                              timeout)
        if self.server_failure(resp, ignore_codes):
            LOG.error(errstr, resp[2])
            raise RemoteRestError(reason=resp[2], status=resp[0])
        if resp[0] in ignore_codes:
            LOG.warning(_("NeutronRestProxyV2: Received and ignored error "
                          "code %(code)s on %(action)s action to resource "
                          "%(resource)s"),
                        {'code': resp[2], 'action': action,
                         'resource': resource})
        return resp

    def rest_create_router(self, tenant_id, router):
        resource = ROUTER_RESOURCE_PATH % tenant_id
        data = {"router": router}
        errstr = _("Unable to create remote router: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_router(self, tenant_id, router, router_id):
        resource = ROUTERS_PATH % (tenant_id, router_id)
        data = {"router": router}
        errstr = _("Unable to update remote router: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_router(self, tenant_id, router_id):
        resource = ROUTERS_PATH % (tenant_id, router_id)
        errstr = _("Unable to delete remote router: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_add_router_interface(self, tenant_id, router_id, intf_details):
        resource = ROUTER_INTF_OP_PATH % (tenant_id, router_id)
        data = {"interface": intf_details}
        errstr = _("Unable to add router interface: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_remove_router_interface(self, tenant_id, router_id, interface_id):
        resource = ROUTER_INTF_PATH % (tenant_id, router_id, interface_id)
        errstr = _("Unable to delete remote intf: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_create_network(self, tenant_id, network):
        resource = NET_RESOURCE_PATH % tenant_id
        data = {"network": network}
        errstr = _("Unable to create remote network: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_network(self, tenant_id, net_id, network):
        resource = NETWORKS_PATH % (tenant_id, net_id)
        data = {"network": network}
        errstr = _("Unable to update remote network: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_network(self, tenant_id, net_id):
        resource = NETWORKS_PATH % (tenant_id, net_id)
        errstr = _("Unable to update remote network: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_create_port(self, tenant_id, net_id, port):
        resource = ATTACHMENT_PATH % (tenant_id, net_id, port["id"])
        data = {"port": port}
        device_id = port.get("device_id")
        if not port["mac_address"] or not device_id:
            # controller only cares about ports attached to devices
            LOG.warning(_("No device MAC attached to port %s. "
                          "Skipping notification to controller."), port["id"])
            return
        data["attachment"] = {"id": device_id,
                              "mac": port["mac_address"]}
        errstr = _("Unable to create remote port: %s")
        self.rest_action('PUT', resource, data, errstr)

    def rest_delete_port(self, tenant_id, network_id, port_id):
        resource = ATTACHMENT_PATH % (tenant_id, network_id, port_id)
        errstr = _("Unable to delete remote port: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def rest_update_port(self, tenant_id, net_id, port):
        # Controller has no update operation for the port endpoint
        # the create PUT method will replace
        self.rest_create_port(tenant_id, net_id, port)

    def rest_create_floatingip(self, tenant_id, floatingip):
        resource = FLOATINGIPS_PATH % (tenant_id, floatingip['id'])
        errstr = _("Unable to create floating IP: %s")
        self.rest_action('PUT', resource, errstr=errstr)

    def rest_update_floatingip(self, tenant_id, floatingip, oldid):
        resource = FLOATINGIPS_PATH % (tenant_id, oldid)
        errstr = _("Unable to update floating IP: %s")
        self.rest_action('PUT', resource, errstr=errstr)

    def rest_delete_floatingip(self, tenant_id, oldid):
        resource = FLOATINGIPS_PATH % (tenant_id, oldid)
        errstr = _("Unable to delete floating IP: %s")
        self.rest_action('DELETE', resource, errstr=errstr)

    def _consistency_watchdog(self, polling_interval=60):
        if 'consistency' not in self.get_capabilities():
            LOG.warning(_("Backend server(s) do not support automated "
                          "consitency checks."))
            return
        while True:
            # If consistency is supported, all we have to do is make any
            # rest call and the consistency header will be added. If it
            # doesn't match, the backend will return a synchronization error
            # that will be handled by the rest_action.
            eventlet.sleep(polling_interval)
            try:
                self.rest_action('GET', HEALTH_PATH)
            except Exception:
                LOG.exception(_("Encountered an error checking controller "
                                "health."))


class HTTPSConnectionWithValidation(httplib.HTTPSConnection):

    # If combined_cert is None, the connection will continue without
    # any certificate validation.
    combined_cert = None

    def connect(self):
        try:
            sock = socket.create_connection((self.host, self.port),
                                            self.timeout, self.source_address)
        except AttributeError:
            # python 2.6 doesn't have the source_address attribute
            sock = socket.create_connection((self.host, self.port),
                                            self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        if self.combined_cert:
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                        cert_reqs=ssl.CERT_REQUIRED,
                                        ca_certs=self.combined_cert)
        else:
            self.sock = ssl.wrap_socket(sock, self.key_file,
                                        self.cert_file,
                                        cert_reqs=ssl.CERT_NONE)
