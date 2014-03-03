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
- HTTP Authentication

"""
import base64
import httplib
import json
import socket

from oslo.config import cfg

from neutron.common import exceptions
from neutron.common import utils
from neutron.openstack.common import log as logging


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
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
BASE_URI = '/networkService/v1.1'
ORCHESTRATION_SERVICE_ID = 'Neutron v2.0'


class RemoteRestError(exceptions.NeutronException):
    message = _("Error in REST call to remote network "
                "controller: %(reason)s")


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, neutron_id, timeout,
                 base_uri, name):
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
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()

    def get_capabilities(self):
        try:
            body = self.rest_call('GET', CAPABILITIES_PATH)[3]
            self.capabilities = json.loads(body)
        except Exception:
            LOG.error(_("Couldn't retrieve capabilities. "
                        "Newer API calls won't be supported."))
        LOG.info(_("The following capabilities were received "
                   "for %(server)s: %(cap)s"), {'server': self.server,
                                                'cap': self.capabilities})
        return self.capabilities

    def rest_call(self, action, resource, data='', headers=None):
        uri = self.base_uri + resource
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['NeutronProxy-Agent'] = self.name
        headers['Instance-ID'] = self.neutron_id
        headers['Orchestration-Service-ID'] = ORCHESTRATION_SERVICE_ID
        if self.auth:
            headers['Authorization'] = self.auth

        LOG.debug(_("ServerProxy: server=%(server)s, port=%(port)d, "
                    "ssl=%(ssl)r"),
                  {'server': self.server, 'port': self.port, 'ssl': self.ssl})
        LOG.debug(_("ServerProxy: resource=%(resource)s, data=%(data)r, "
                    "headers=%(headers)r, action=%(action)s"),
                  {'resource': resource, 'data': data, 'headers': headers,
                   'action': action})

        conn = None
        if self.ssl:
            conn = httplib.HTTPSConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error(_('ServerProxy: Could not establish HTTPS '
                            'connection'))
                return 0, None, None, None
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error(_('ServerProxy: Could not establish HTTP '
                            'connection'))
                return 0, None, None, None

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except (socket.timeout, socket.error) as e:
            LOG.error(_('ServerProxy: %(action)s failure, %(e)r'),
                      {'action': action, 'e': e})
            ret = 0, None, None, None
        conn.close()
        LOG.debug(_("ServerProxy: status=%(status)d, reason=%(reason)r, "
                    "ret=%(ret)s, data=%(data)r"), {'status': ret[0],
                                                    'reason': ret[1],
                                                    'ret': ret[2],
                                                    'data': ret[3]})
        return ret


class ServerPool(object):

    def __init__(self, timeout=10,
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
        self.timeout = cfg.CONF.RESTPROXY.server_timeout
        default_port = 8000
        if timeout is not None:
            self.timeout = timeout

        if not servers:
            raise cfg.Error(_('Servers not defined. Aborting server manager.'))
        servers = [s if len(s.rsplit(':', 1)) == 2
                   else "%s:%d" % (s, default_port)
                   for s in servers]
        if any((len(spl) != 2)for spl in [sp.rsplit(':', 1)
                                          for sp in servers]):
            raise cfg.Error(_('Servers must be defined as <ip>:<port>. '
                              'Configuration was %s') % servers)
        self.servers = [
            self.server_proxy_for(server, int(port))
            for server, port in (s.rsplit(':', 1) for s in servers)
        ]
        LOG.debug(_("ServerPool: initialization done"))

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
        return ServerProxy(server, port, self.ssl, self.auth, self.neutron_id,
                           self.timeout, self.base_uri, self.name)

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
    def rest_call(self, action, resource, data, headers, ignore_codes):
        good_first = sorted(self.servers, key=lambda x: x.failed)
        for active_server in good_first:
            ret = active_server.rest_call(action, resource, data, headers)
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
        return (0, None, None, None)

    def rest_action(self, action, resource, data='', errstr='%s',
                    ignore_codes=[], headers=None):
        """
        Wrapper for rest_call that verifies success and raises a
        RemoteRestError on failure with a provided error string
        By default, 404 errors on DELETE calls are ignored because
        they already do not exist on the backend.
        """
        if not ignore_codes and action == 'DELETE':
            ignore_codes = [404]
        resp = self.rest_call(action, resource, data, headers, ignore_codes)
        if self.server_failure(resp, ignore_codes):
            LOG.error(errstr, resp[2])
            raise RemoteRestError(reason=resp[2])
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
