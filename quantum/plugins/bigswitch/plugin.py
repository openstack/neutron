# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Big Switch Networks, Inc.
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

"""
Quantum REST Proxy Plug-in for Big Switch and FloodLight Controllers

QuantumRestProxy provides a generic quantum plugin that translates all plugin
function calls to equivalent authenticated REST calls to a set of redundant
external network controllers. It also keeps persistent store for all quantum
state to allow for re-sync of the external controller(s), if required.

The local state on the plugin also allows for local response and fast-fail
semantics where it can be determined based on the local persistent store.

Network controller specific code is decoupled from this plugin and expected
to reside on the controller itself (via the REST interface).

This allows for:
 - independent authentication and redundancy schemes between quantum and the
   network controller
 - independent upgrade/development cycles between quantum and the controller
   as it limits the proxy code upgrade requirement to quantum release cycle
   and the controller specific code upgrade requirement to controller code
 - ability to sync the controller with quantum for independent recovery/reset

External REST API used by proxy is the same API as defined for quantum (JSON
subset) with some additional parameters (gateway on network-create and macaddr
on port-attach) on an additional PUT to do a bulk dump of all persistent data.
"""

import base64
import httplib
import json
import socket

from quantum.common import exceptions
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum import context as qcontext
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.plugins.bigswitch.version import version_string_with_vcs


LOG = logging.getLogger(__name__)


database_opts = [
    cfg.StrOpt('sql_connection', default='sqlite://'),
    cfg.IntOpt('sql_max_retries', default=-1),
    cfg.IntOpt('reconnect_interval', default=2),
]


restproxy_opts = [
    cfg.StrOpt('servers', default='localhost:8800'),
    cfg.StrOpt('serverauth', default='username:password'),
    cfg.BoolOpt('serverssl', default=False),
    cfg.BoolOpt('syncdata', default=False),
    cfg.IntOpt('servertimeout', default=10),
]


cfg.CONF.register_opts(database_opts, "DATABASE")
cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")


# The following are used to invoke the API on the external controller
NET_RESOURCE_PATH = "/tenants/%s/networks"
PORT_RESOURCE_PATH = "/tenants/%s/networks/%s/ports"
NETWORKS_PATH = "/tenants/%s/networks/%s"
PORTS_PATH = "/tenants/%s/networks/%s/ports/%s"
ATTACHMENT_PATH = "/tenants/%s/networks/%s/ports/%s/attachment"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
SYNTAX_ERROR_MESSAGE = 'Syntax error in server config file, aborting plugin'


class RemoteRestError(exceptions.QuantumException):
    def __init__(self, message):
        if message is None:
            message = "None"
        self.message = _("Error in REST call to remote network "
                         "controller") + ": " + message
        super(RemoteRestError, self).__init__()


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, timeout, base_uri, name):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = SUCCESS_CODES
        self.auth = None
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()

    def rest_call(self, action, resource, data, headers):
        uri = self.base_uri + resource
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['QuantumProxy-Agent'] = self.name
        if self.auth:
            headers['Authorization'] = self.auth

        LOG.debug('ServerProxy: server=%s, port=%d, ssl=%r, action=%s' %
                  (self.server, self.port, self.ssl, action))
        LOG.debug('ServerProxy: resource=%s, data=%r, headers=%r' %
                  (resource, data, headers))

        conn = None
        if self.ssl:
            conn = httplib.HTTPSConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error('ServerProxy: Could not establish HTTPS connection')
                return 0, None, None, None
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error('ServerProxy: Could not establish HTTP connection')
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
            LOG.error('ServerProxy: %s failure, %r' % (action, e))
            ret = 0, None, None, None
        conn.close()
        LOG.debug('ServerProxy: status=%d, reason=%r, ret=%s, data=%r' % ret)
        return ret


class ServerPool(object):
    def __init__(self, servers, ssl, auth, timeout=10,
                 base_uri='/quantum/v1.0', name='QuantumRestProxy'):
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.auth = auth
        self.ssl = ssl
        self.servers = []
        for server_port in servers:
            self.servers.append(self.server_proxy_for(*server_port))

    def server_proxy_for(self, server, port):
        return ServerProxy(server, port, self.ssl, self.auth, self.timeout,
                           self.base_uri, self.name)

    def server_failure(self, resp):
        """Define failure codes as required.
        Note: We assume 301-303 is a failure, and try the next server in
        the server pool.
        """
        return resp[0] in FAILURE_CODES

    def action_success(self, resp):
        """Defining success codes as required.
        Note: We assume any valid 2xx as being successful response.
        """
        return resp[0] in SUCCESS_CODES

    def rest_call(self, action, resource, data, headers):
        failed_servers = []
        while self.servers:
            active_server = self.servers[0]
            ret = active_server.rest_call(action, resource, data, headers)
            if not self.server_failure(ret):
                self.servers.extend(failed_servers)
                return ret
            else:
                LOG.error('ServerProxy: %s failure for servers: %r' % (
                    action, (active_server.server, active_server.port)))
                failed_servers.append(self.servers.pop(0))

        # All servers failed, reset server list and try again next time
        LOG.error('ServerProxy: %s failure for all servers: %r' % (
            action, tuple((s.server, s.port) for s in failed_servers)))
        self.servers.extend(failed_servers)
        return (0, None, None, None)

    def get(self, resource, data='', headers=None):
        return self.rest_call('GET', resource, data, headers)

    def put(self, resource, data, headers=None):
        return self.rest_call('PUT', resource, data, headers)

    def post(self, resource, data, headers=None):
        return self.rest_call('POST', resource, data, headers)

    def delete(self, resource, data='', headers=None):
        return self.rest_call('DELETE', resource, data, headers)


class RpcProxy(dhcp_rpc_base.DhcpRpcCallbackMixin):

    RPC_API_VERSION = '1.0'

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])


class QuantumRestProxyV2(db_base_plugin_v2.QuantumDbPluginV2):

    def __init__(self):
        LOG.info('QuantumRestProxy: Starting plugin. Version=%s' %
                 version_string_with_vcs())

        # init DB, proxy's persistent store defaults to in-memory sql-lite DB
        options = {"sql_connection": "%s" % cfg.CONF.DATABASE.sql_connection,
                   "sql_max_retries": cfg.CONF.DATABASE.sql_max_retries,
                   "reconnect_interval": cfg.CONF.DATABASE.reconnect_interval,
                   "base": models_v2.model_base.BASEV2}
        db.configure_db(options)

        # 'servers' is the list of network controller REST end-points
        # (used in order specified till one suceeds, and it is sticky
        # till next failure). Use 'serverauth' to encode api-key
        servers = cfg.CONF.RESTPROXY.servers
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        syncdata = cfg.CONF.RESTPROXY.syncdata
        timeout = cfg.CONF.RESTPROXY.servertimeout

        # validate config
        assert servers is not None, 'Servers not defined. Aborting plugin'
        servers = tuple(s.rsplit(':', 1) for s in servers.split(','))
        servers = tuple((server, int(port)) for server, port in servers)
        assert all(len(s) == 2 for s in servers), SYNTAX_ERROR_MESSAGE

        # init network ctrl connections
        self.servers = ServerPool(servers, serverssl, serverauth,
                                  timeout)

        # init dhcp support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.callbacks = RpcProxy()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        if syncdata:
            self._send_all_data()

        LOG.debug("QuantumRestProxyV2: initialization done")

    def create_network(self, context, network):
        """Create a network, which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        :param context: quantum api request context
        :param network: dictionary describing the network

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can specify
                         a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxyV2: create_network() called")

        # Validate args
        tenant_id = self._get_tenant_id_for_create(context, network["network"])
        net_name = network["network"]["name"]
        if network["network"]["admin_state_up"] is False:
            LOG.warning("Network with admin_state_up=False are not yet "
                        "supported by this plugin. Ignoring setting for "
                        "network %s", net_name)

        # create in DB
        new_net = super(QuantumRestProxyV2, self).create_network(context,
                                                                 network)

        # create on networl ctrl
        try:
            resource = NET_RESOURCE_PATH % tenant_id
            data = {
                "network": {
                    "id": new_net["id"],
                    "name": new_net["name"],
                }
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to create remote network:%s" %
                      e.message)
            super(QuantumRestProxyV2, self).delete_network(context,
                                                           new_net['id'])
            raise

        # return created network
        return new_net

    def update_network(self, context, net_id, network):
        """Updates the properties of a particular Virtual Network.
        :param context: quantum api request context
        :param net_id: uuid of the network to update
        :param network: dictionary describing the updates

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can
                         specify a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxyV2.update_network() called")

        # Validate Args
        if network["network"].get("admin_state_up"):
            if network["network"]["admin_state_up"] is False:
                LOG.warning("Network with admin_state_up=False are not yet "
                            "supported by this plugin. Ignoring setting for "
                            "network %s", net_name)

        # update DB
        orig_net = super(QuantumRestProxyV2, self).get_network(context, net_id)
        tenant_id = orig_net["tenant_id"]
        new_net = super(QuantumRestProxyV2, self).update_network(
            context, net_id, network)

        # update network on network controller
        if new_net["name"] != orig_net["name"]:
            try:
                resource = NETWORKS_PATH % (tenant_id, net_id)
                data = {
                    "network": new_net,
                }
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])
            except RemoteRestError as e:
                LOG.error(
                    "QuantumRestProxyV2: Unable to update remote network: %s" %
                    e.message)
                # reset network to original state
                super(QuantumRestProxyV2, self).update_network(
                    context, id, orig_net)
                raise

        # return updated network
        return new_net

    def delete_network(self, context, net_id):
        """Delete a network.
        :param context: quantum api request context
        :param id: UUID representing the network to delete.

        :returns: None

        :raises: exceptions.NetworkInUse
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: delete_network() called")

        # Validate args
        orig_net = super(QuantumRestProxyV2, self).get_network(context, net_id)
        tenant_id = orig_net["tenant_id"]

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = NETWORKS_PATH % (tenant_id, net_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            ret_val = super(QuantumRestProxyV2, self).delete_network(context,
                                                                     net_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote network: %s" %
                e.message)

    def create_port(self, context, port):
        """Create a port, which is a connection point of a device
        (e.g., a VM NIC) to attach to a L2 Quantum network.
        :param context: quantum api request context
        :param port: dictionary describing the port

        :returns:
        {
            "id": uuid represeting the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": Sets admin state of port. if down, port
                              does not forward packets.
            "status": dicates whether port is currently operational
                      (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet ID"s and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.StateInvalid
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: create_port() called")

        # Update DB
        port["port"]["admin_state_up"] = False
        new_port = super(QuantumRestProxyV2, self).create_port(context, port)
        net = super(QuantumRestProxyV2,
                    self).get_network(context, new_port["network_id"])

        # create on networl ctrl
        try:
            resource = PORT_RESOURCE_PATH % (net["tenant_id"], net["id"])
            data = {
                "port": {
                    "id": new_port["id"],
                    "state": "ACTIVE",
                }
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            # connect device to network, if present
            if port["port"].get("device_id"):
                self._plug_interface(context,
                                     net["tenant_id"], net["id"],
                                     new_port["id"], new_port["id"] + "00")
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2: Unable to create remote port: %s" %
                      e.message)
            super(QuantumRestProxyV2, self).delete_port(context,
                                                        new_port["id"])
            raise

        # Set port state up and return that port
        port_update = {"port": {"admin_state_up": True}}
        return super(QuantumRestProxyV2, self).update_port(context,
                                                           new_port["id"],
                                                           port_update)

    def update_port(self, context, port_id, port):
        """Update values of a port.
        :param context: quantum api request context
        :param id: UUID representing the port to update.
        :param port: dictionary with keys indicating fields to update.

        :returns: a mapping sequence with the following signature:
        {
            "id": uuid represeting the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": sets admin state of port. if down, port
                               does not forward packets.
            "status": dicates whether port is currently operational
                       (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet ID's and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.StateInvalid
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: update_port() called")

        # Validate Args
        orig_port = super(QuantumRestProxyV2, self).get_port(context, port_id)

        # Update DB
        new_port = super(QuantumRestProxyV2, self).update_port(context,
                                                               port_id, port)

        # update on networl ctrl
        try:
            resource = PORTS_PATH % (orig_port["tenant_id"],
                                     orig_port["network_id"], port_id)
            data = {"port": new_port, }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            if new_port.get("device_id") != orig_port.get("device_id"):
                if orig_port.get("device_id"):
                    self._unplug_interface(context, orig_port["tenant_id"],
                                           orig_port["network_id"],
                                           orig_port["id"])
                if new_port.get("device_id"):
                    self._plug_interface(context, new_port["tenant_id"],
                                         new_port["network_id"],
                                         new_port["id"], new_port["id"] + "00")

        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to create remote port: %s" %
                e.message)
            # reset port to original state
            super(QuantumRestProxyV2, self).update_port(context, port_id,
                                                        orig_port)
            raise

        # return new_port
        return new_port

    def delete_port(self, context, port_id):
        """Delete a port.
        :param context: quantum api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxyV2: delete_port() called")

        # Delete from DB
        port = super(QuantumRestProxyV2, self).get_port(context, port_id)

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = PORTS_PATH % (port["tenant_id"], port["network_id"],
                                     port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            if port.get("device_id"):
                self._unplug_interface(context, port["tenant_id"],
                                       port["network_id"], port["id"])
            ret_val = super(QuantumRestProxyV2, self).delete_port(context,
                                                                  port_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote port: %s" %
                e.message)

    def _plug_interface(self, context, tenant_id, net_id, port_id,
                        remote_interface_id):
        """Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: _plug_interface() called")

        # update attachment on network controller
        try:
            port = super(QuantumRestProxyV2, self).get_port(context, port_id)
            mac = port["mac_address"]

            for ip in port["fixed_ips"]:
                if ip.get("subnet_id") is not None:
                    subnet = super(QuantumRestProxyV2, self).get_subnet(
                        context, ip["subnet_id"])
                    gateway = subnet.get("gateway_ip")
                    if gateway is not None:
                        resource = NETWORKS_PATH % (tenant_id, net_id)
                        data = {"network":
                                {"id": net_id,
                                 "gateway": gateway,
                                 }
                                }
                        ret = self.servers.put(resource, data)
                        if not self.servers.action_success(ret):
                            raise RemoteRestError(ret[2])

            if mac is not None:
                resource = ATTACHMENT_PATH % (tenant_id, net_id, port_id)
                data = {"attachment":
                        {"id": remote_interface_id,
                         "mac": mac,
                         }
                        }
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to update remote network:%s" %
                      e.message)
            raise

    def _unplug_interface(self, context, tenant_id, net_id, port_id):
        """Detaches a remote interface from the specified port on the
        network controller

        :returns: None

        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: _unplug_interface() called")

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = ATTACHMENT_PATH % (tenant_id, net_id, port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote port: %s" %
                e.message)

    def _send_all_data(self):
        """Pushes all data to network ctrl (networks/ports, ports/attachments)
        to give the controller an option to re-sync it's persistent store
        with quantum's current view of that data.
        """
        admin_context = qcontext.get_admin_context()
        networks = {}
        ports = {}

        all_networks = super(QuantumRestProxyV2,
                             self).get_networks(admin_context) or []
        for net in all_networks:
            networks[net.get('id')] = {
                'id': net.get('id'),
                'name': net.get('name'),
                'op-status': net.get('admin_state_up'),
            }

            subnets = net.get('subnets', [])
            for subnet_id in subnets:
                subnet = self.get_subnet(admin_context, subnet_id)
                gateway_ip = subnet.get('gateway_ip')
                if gateway_ip:
                    # FIX: For backward compatibility with wire protocol
                    networks[net.get('id')]['gateway'] = gateway_ip

            ports = []
            net_filter = {'network_id': [net.get('id')]}
            net_ports = super(QuantumRestProxyV2,
                              self).get_ports(admin_context,
                                              filters=net_filter) or []
            for port in net_ports:
                port_details = {
                    'id': port.get('id'),
                    'attachment': {
                        'id': port.get('id') + '00',
                        'mac': port.get('mac_address'),
                    },
                    'state': port.get('status'),
                    'op-status': port.get('admin_state_up'),
                    'mac': None
                }
                ports.append(port_details)
            networks[net.get('id')]['ports'] = ports
        try:
            resource = '/topology'
            data = {
                'networks': networks,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            return ret
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote network: %s' %
                e.message)
            raise
