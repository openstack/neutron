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
import copy
import httplib
import json
import socket

from oslo.config import cfg

from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.common import constants as const
from quantum.common import exceptions
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.common import utils
from quantum import context as qcontext
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_db
from quantum.extensions import l3
from quantum.extensions import portbindings
from quantum.openstack.common import lockutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.plugins.bigswitch.version import version_string_with_vcs
from quantum import policy


LOG = logging.getLogger(__name__)


restproxy_opts = [
    cfg.StrOpt('servers', default='localhost:8800',
               help=_("A comma separated list of servers and port numbers "
                      "to proxy request to.")),
    cfg.StrOpt('server_auth', default='username:password', secret=True,
               help=_("Server authentication")),
    cfg.BoolOpt('server_ssl', default=False,
                help=_("Use SSL to connect")),
    cfg.BoolOpt('sync_data', default=False,
                help=_("Sync data on connect")),
    cfg.IntOpt('server_timeout', default=10,
               help=_("Maximum number of seconds to wait for proxy request "
                      "to connect and complete.")),
    cfg.StrOpt('quantum_id', default='Quantum-' + utils.get_hostname(),
               help=_("User defined identifier for this Quantum deployment")),
    cfg.BoolOpt('add_meta_server_route', default=True,
                help=_("Flag to decide if a route to the metadata server "
                       "should be injected into the VM")),
]


cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")


# The following are used to invoke the API on the external controller
NET_RESOURCE_PATH = "/tenants/%s/networks"
PORT_RESOURCE_PATH = "/tenants/%s/networks/%s/ports"
ROUTER_RESOURCE_PATH = "/tenants/%s/routers"
ROUTER_INTF_OP_PATH = "/tenants/%s/routers/%s/interfaces"
NETWORKS_PATH = "/tenants/%s/networks/%s"
PORTS_PATH = "/tenants/%s/networks/%s/ports/%s"
ATTACHMENT_PATH = "/tenants/%s/networks/%s/ports/%s/attachment"
ROUTERS_PATH = "/tenants/%s/routers/%s"
ROUTER_INTF_PATH = "/tenants/%s/routers/%s/interfaces/%s"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
SYNTAX_ERROR_MESSAGE = 'Syntax error in server config file, aborting plugin'
BASE_URI = '/networkService/v1.1'
ORCHESTRATION_SERVICE_ID = 'Quantum v2.0'
METADATA_SERVER_IP = '169.254.169.254'


class RemoteRestError(exceptions.QuantumException):
    def __init__(self, message):
        if message is None:
            message = "None"
        self.message = _("Error in REST call to remote network "
                         "controller") + ": " + message
        super(RemoteRestError, self).__init__()


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, quantum_id, timeout,
                 base_uri, name):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = SUCCESS_CODES
        self.auth = None
        self.quantum_id = quantum_id
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()

    @lockutils.synchronized('rest_call', 'bsn-', external=True)
    def rest_call(self, action, resource, data, headers):
        uri = self.base_uri + resource
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['QuantumProxy-Agent'] = self.name
        headers['Instance-ID'] = self.quantum_id
        headers['Orchestration-Service-ID'] = ORCHESTRATION_SERVICE_ID
        if self.auth:
            headers['Authorization'] = self.auth

        LOG.debug(_("ServerProxy: server=%(server)s, port=%(port)d, "
                    "ssl=%(ssl)r, action=%(action)s"),
                  {'server': self.server, 'port': self.port, 'ssl': self.ssl,
                   'action': action})
        LOG.debug(_("ServerProxy: resource=%(resource)s, data=%(data)r, "
                    "headers=%(headers)r"), locals())

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
            LOG.error(_('ServerProxy: %(action)s failure, %(e)r'), locals())
            ret = 0, None, None, None
        conn.close()
        LOG.debug(_("ServerProxy: status=%(status)d, reason=%(reason)r, "
                    "ret=%(ret)s, data=%(data)r"), {'status': ret[0],
                                                    'reason': ret[1],
                                                    'ret': ret[2],
                                                    'data': ret[3]})
        return ret


class ServerPool(object):
    def __init__(self, servers, ssl, auth, quantum_id, timeout=10,
                 base_uri='/quantum/v1.0', name='QuantumRestProxy'):
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.auth = auth
        self.ssl = ssl
        self.quantum_id = quantum_id
        self.servers = []
        for server_port in servers:
            self.servers.append(self.server_proxy_for(*server_port))

    def server_proxy_for(self, server, port):
        return ServerProxy(server, port, self.ssl, self.auth, self.quantum_id,
                           self.timeout, self.base_uri, self.name)

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
                LOG.error(_('ServerProxy: %(action)s failure for servers: '
                            '%(server)r'),
                          {'action': action,
                           'server': (active_server.server,
                                      active_server.port)})
                failed_servers.append(self.servers.pop(0))

        # All servers failed, reset server list and try again next time
        LOG.error(_('ServerProxy: %(action)s failure for all servers: '
                    '%(server)r'),
                  {'action': action,
                   'server': tuple((s.server,
                                    s.port) for s in failed_servers)})
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


class QuantumRestProxyV2(db_base_plugin_v2.QuantumDbPluginV2,
                         l3_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router", "binding"]

    binding_view = "extension:port_binding:view"
    binding_set = "extension:port_binding:set"

    def __init__(self):
        LOG.info(_('QuantumRestProxy: Starting plugin. Version=%s'),
                 version_string_with_vcs())

        # init DB, proxy's persistent store defaults to in-memory sql-lite DB
        db.configure_db()

        # 'servers' is the list of network controller REST end-points
        # (used in order specified till one suceeds, and it is sticky
        # till next failure). Use 'server_auth' to encode api-key
        servers = cfg.CONF.RESTPROXY.servers
        server_auth = cfg.CONF.RESTPROXY.server_auth
        server_ssl = cfg.CONF.RESTPROXY.server_ssl
        sync_data = cfg.CONF.RESTPROXY.sync_data
        timeout = cfg.CONF.RESTPROXY.server_timeout
        quantum_id = cfg.CONF.RESTPROXY.quantum_id
        self.add_meta_server_route = cfg.CONF.RESTPROXY.add_meta_server_route

        # validate config
        assert servers is not None, 'Servers not defined. Aborting plugin'
        servers = tuple(s.rsplit(':', 1) for s in servers.split(','))
        servers = tuple((server, int(port)) for server, port in servers)
        assert all(len(s) == 2 for s in servers), SYNTAX_ERROR_MESSAGE

        # init network ctrl connections
        self.servers = ServerPool(servers, server_ssl, server_auth, quantum_id,
                                  timeout, BASE_URI)

        # init dhcp support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.callbacks = RpcProxy()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        if sync_data:
            self._send_all_data()

        self._dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        LOG.debug(_("QuantumRestProxyV2: initialization done"))

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

        LOG.debug(_("QuantumRestProxyV2: create_network() called"))

        self._warn_on_state_status(network['network'])

        # Validate args
        tenant_id = self._get_tenant_id_for_create(context, network["network"])

        session = context.session
        with session.begin(subtransactions=True):
            # create network in DB
            new_net = super(QuantumRestProxyV2, self).create_network(context,
                                                                     network)
            self._process_l3_create(context, network['network'], new_net['id'])
            self._extend_network_dict_l3(context, new_net)

        # create network on the network controller
        try:
            resource = NET_RESOURCE_PATH % tenant_id
            mapped_network = self._get_mapped_network_with_subnets(new_net)
            data = {
                "network": mapped_network
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2:Unable to create remote "
                        "network: %s"), e.message)
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

        LOG.debug(_("QuantumRestProxyV2.update_network() called"))

        self._warn_on_state_status(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                                   net_id)
            new_net = super(QuantumRestProxyV2, self).update_network(context,
                                                                     net_id,
                                                                     network)
            self._process_l3_update(context, network['network'], net_id)
            self._extend_network_dict_l3(context, new_net)

        # update network on network controller
        try:
            self._send_update_network(new_net)
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to update remote "
                        "network: %s"), e.message)
            # reset network to original state
            super(QuantumRestProxyV2, self).update_network(context, id,
                                                           orig_net)
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
        LOG.debug(_("QuantumRestProxyV2: delete_network() called"))

        # Validate args
        orig_net = super(QuantumRestProxyV2, self).get_network(context, net_id)
        tenant_id = orig_net["tenant_id"]

        filter = {'network_id': [net_id]}
        ports = self.get_ports(context, filters=filter)

        # check if there are any tenant owned ports in-use
        auto_delete_port_owners = db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
        only_auto_del = all(p['device_owner'] in auto_delete_port_owners
                            for p in ports)

        if not only_auto_del:
            raise exceptions.NetworkInUse(net_id=net_id)

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
            LOG.error(_("QuantumRestProxyV2: Unable to update remote "
                        "network: %s"), e.message)
            raise

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
        LOG.debug(_("QuantumRestProxyV2: create_port() called"))

        # Update DB
        port["port"]["admin_state_up"] = False
        new_port = super(QuantumRestProxyV2, self).create_port(context, port)
        net = super(QuantumRestProxyV2,
                    self).get_network(context, new_port["network_id"])

        if self.add_meta_server_route:
            if new_port['device_owner'] == 'network:dhcp':
                destination = METADATA_SERVER_IP + '/32'
                self._add_host_route(context, destination, new_port)

        # create on networl ctrl
        try:
            resource = PORT_RESOURCE_PATH % (net["tenant_id"], net["id"])
            mapped_port = self._map_state_and_status(new_port)
            data = {
                "port": mapped_port
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            # connect device to network, if present
            device_id = port["port"].get("device_id")
            if device_id:
                self._plug_interface(context,
                                     net["tenant_id"], net["id"],
                                     new_port["id"], device_id)
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to create remote port: "
                        "%s"), e.message)
            super(QuantumRestProxyV2, self).delete_port(context,
                                                        new_port["id"])
            raise

        # Set port state up and return that port
        port_update = {"port": {"admin_state_up": True}}
        new_port = super(QuantumRestProxyV2, self).update_port(context,
                                                               new_port["id"],
                                                               port_update)
        return self._extend_port_dict_binding(context, new_port)

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(QuantumRestProxyV2, self).get_port(context, id,
                                                            fields)
            self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports = super(QuantumRestProxyV2, self).get_ports(context, filters,
                                                              fields)
            for port in ports:
                self._extend_port_dict_binding(context, port)
        return [self._fields(port, fields) for port in ports]

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
        LOG.debug(_("QuantumRestProxyV2: update_port() called"))

        self._warn_on_state_status(port['port'])

        # Validate Args
        orig_port = super(QuantumRestProxyV2, self).get_port(context, port_id)

        # Update DB
        new_port = super(QuantumRestProxyV2, self).update_port(context,
                                                               port_id, port)

        # update on networl ctrl
        try:
            resource = PORTS_PATH % (orig_port["tenant_id"],
                                     orig_port["network_id"], port_id)
            mapped_port = self._map_state_and_status(new_port)
            data = {"port": mapped_port}
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            if new_port.get("device_id") != orig_port.get("device_id"):
                if orig_port.get("device_id"):
                    self._unplug_interface(context, orig_port["tenant_id"],
                                           orig_port["network_id"],
                                           orig_port["id"])
                device_id = new_port.get("device_id")
                if device_id:
                    self._plug_interface(context, new_port["tenant_id"],
                                         new_port["network_id"],
                                         new_port["id"], device_id)

        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to create remote port: "
                        "%s"), e.message)
            # reset port to original state
            super(QuantumRestProxyV2, self).update_port(context, port_id,
                                                        orig_port)
            raise

        # return new_port
        return self._extend_port_dict_binding(context, new_port)

    def delete_port(self, context, port_id, l3_port_check=True):
        """Delete a port.
        :param context: quantum api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """

        LOG.debug(_("QuantumRestProxyV2: delete_port() called"))

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        self.disassociate_floatingips(context, port_id)

        super(QuantumRestProxyV2, self).delete_port(context, port_id)

    def _delete_port(self, context, port_id):
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
            ret_val = super(QuantumRestProxyV2, self)._delete_port(context,
                                                                   port_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to update remote port: "
                        "%s"), e.message)
            raise

    def _plug_interface(self, context, tenant_id, net_id, port_id,
                        remote_interface_id):
        """Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        LOG.debug(_("QuantumRestProxyV2: _plug_interface() called"))

        # update attachment on network controller
        try:
            port = super(QuantumRestProxyV2, self).get_port(context, port_id)
            mac = port["mac_address"]

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
            LOG.error(_("QuantumRestProxyV2:Unable to update remote network: "
                        "%s"), e.message)
            raise

    def _unplug_interface(self, context, tenant_id, net_id, port_id):
        """Detaches a remote interface from the specified port on the
        network controller

        :returns: None

        :raises: RemoteRestError
        """
        LOG.debug(_("QuantumRestProxyV2: _unplug_interface() called"))

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = ATTACHMENT_PATH % (tenant_id, net_id, port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to update remote port: "
                        "%s"), e.message)

    def create_subnet(self, context, subnet):
        LOG.debug(_("QuantumRestProxyV2: create_subnet() called"))

        self._warn_on_state_status(subnet['subnet'])

        # create subnet in DB
        new_subnet = super(QuantumRestProxyV2, self).create_subnet(context,
                                                                   subnet)
        net_id = new_subnet['network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError:
            # rollback creation of subnet
            super(QuantumRestProxyV2, self).delete_subnet(context,
                                                          subnet['id'])
            raise
        return new_subnet

    def update_subnet(self, context, id, subnet):
        LOG.debug(_("QuantumRestProxyV2: update_subnet() called"))

        self._warn_on_state_status(subnet['subnet'])

        orig_subnet = super(QuantumRestProxyV2, self)._get_subnet(context, id)

        # update subnet in DB
        new_subnet = super(QuantumRestProxyV2, self).update_subnet(context, id,
                                                                   subnet)
        net_id = new_subnet['network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError:
            # rollback updation of subnet
            super(QuantumRestProxyV2, self).update_subnet(context, id,
                                                          orig_subnet)
            raise
        return new_subnet

    def delete_subnet(self, context, id):
        LOG.debug(_("QuantumRestProxyV2: delete_subnet() called"))
        orig_subnet = super(QuantumRestProxyV2, self).get_subnet(context, id)
        net_id = orig_subnet['network_id']
        # delete subnet in DB
        super(QuantumRestProxyV2, self).delete_subnet(context, id)
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError:
            # TODO (Sumit): rollback deletion of subnet
            raise

    def create_router(self, context, router):
        LOG.debug(_("QuantumRestProxyV2: create_router() called"))

        self._warn_on_state_status(router['router'])

        tenant_id = self._get_tenant_id_for_create(context, router["router"])

        # create router in DB
        new_router = super(QuantumRestProxyV2, self).create_router(context,
                                                                   router)

        # create router on the network controller
        try:
            resource = ROUTER_RESOURCE_PATH % tenant_id
            mapped_router = self._map_state_and_status(new_router)
            data = {
                "router": mapped_router
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to create remote router: "
                        "%s"), e.message)
            super(QuantumRestProxyV2, self).delete_router(context,
                                                          new_router['id'])
            raise

        # return created router
        return new_router

    def update_router(self, context, router_id, router):

        LOG.debug(_("QuantumRestProxyV2.update_router() called"))

        self._warn_on_state_status(router['router'])

        orig_router = super(QuantumRestProxyV2, self).get_router(context,
                                                                 router_id)
        tenant_id = orig_router["tenant_id"]
        new_router = super(QuantumRestProxyV2, self).update_router(context,
                                                                   router_id,
                                                                   router)

        # update router on network controller
        try:
            resource = ROUTERS_PATH % (tenant_id, router_id)
            mapped_router = self._map_state_and_status(new_router)
            data = {
                "router": mapped_router
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to update remote router: "
                        "%s"), e.message)
            # reset router to original state
            super(QuantumRestProxyV2, self).update_router(context,
                                                          router_id,
                                                          orig_router)
            raise

        # return updated router
        return new_router

    def delete_router(self, context, router_id):
        LOG.debug(_("QuantumRestProxyV2: delete_router() called"))

        with context.session.begin(subtransactions=True):
            orig_router = self._get_router(context, router_id)
            tenant_id = orig_router["tenant_id"]

            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_owner = l3_db.DEVICE_OWNER_ROUTER_INTF
            device_filter = {'device_id': [router_id],
                             'device_owner': [device_owner]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = ROUTERS_PATH % (tenant_id, router_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            ret_val = super(QuantumRestProxyV2, self).delete_router(context,
                                                                    router_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to delete remote router: "
                        "%s"), e.message)
            raise

    def add_router_interface(self, context, router_id, interface_info):

        LOG.debug(_("QuantumRestProxyV2: add_router_interface() called"))

        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # create interface in DB
        new_interface_info = super(QuantumRestProxyV2,
                                   self).add_router_interface(context,
                                                              router_id,
                                                              interface_info)
        port = self._get_port(context, new_interface_info['port_id'])
        net_id = port['network_id']
        subnet_id = new_interface_info['subnet_id']
        # we will use the port's network id as interface's id
        interface_id = net_id
        intf_details = self._get_router_intf_details(context,
                                                     interface_id,
                                                     subnet_id)

        # create interface on the network controller
        try:
            resource = ROUTER_INTF_OP_PATH % (tenant_id, router_id)
            data = {"interface": intf_details}
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to create interface: "
                        "%s"), e.message)
            super(QuantumRestProxyV2,
                  self).remove_router_interface(context, router_id,
                                                interface_info)
            raise

        return new_interface_info

    def remove_router_interface(self, context, router_id, interface_info):

        LOG.debug(_("QuantumRestProxyV2: remove_router_interface() called"))

        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # we will first get the interface identifier before deleting in the DB
        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise exceptions.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port = self._get_port(context, interface_info['port_id'])
            interface_id = port['network_id']
        elif 'subnet_id' in interface_info:
            subnet = self._get_subnet(context, interface_info['subnet_id'])
            interface_id = subnet['network_id']
        else:
            msg = "Either subnet_id or port_id must be specified"
            raise exceptions.BadRequest(resource='router', msg=msg)

        # remove router in DB
        del_intf_info = super(QuantumRestProxyV2,
                              self).remove_router_interface(context,
                                                            router_id,
                                                            interface_info)

        # create router on the network controller
        try:
            resource = ROUTER_INTF_PATH % (tenant_id, router_id, interface_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2:Unable to delete remote intf: "
                        "%s"), e.message)
            raise

        # return new interface
        return del_intf_info

    def create_floatingip(self, context, floatingip):
        LOG.debug(_("QuantumRestProxyV2: create_floatingip() called"))

        # create floatingip in DB
        new_fl_ip = super(QuantumRestProxyV2,
                          self).create_floatingip(context, floatingip)

        net_id = new_fl_ip['floating_network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # create floatingip on the network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to create remote "
                        "floatin IP: %s"), e.message)
            super(QuantumRestProxyV2, self).delete_floatingip(context,
                                                              floatingip)
            raise

        # return created floating IP
        return new_fl_ip

    def update_floatingip(self, context, id, floatingip):
        LOG.debug(_("QuantumRestProxyV2: update_floatingip() called"))

        orig_fl_ip = super(QuantumRestProxyV2, self).get_floatingip(context,
                                                                    id)

        # update floatingip in DB
        new_fl_ip = super(QuantumRestProxyV2,
                          self).update_floatingip(context, id, floatingip)

        net_id = new_fl_ip['floating_network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError:
            # rollback updation of subnet
            super(QuantumRestProxyV2, self).update_floatingip(context, id,
                                                              orig_fl_ip)
            raise
        return new_fl_ip

    def delete_floatingip(self, context, id):
        LOG.debug(_("QuantumRestProxyV2: delete_floatingip() called"))

        orig_fl_ip = super(QuantumRestProxyV2, self).get_floatingip(context,
                                                                    id)
        # delete floating IP in DB
        net_id = orig_fl_ip['floating_network_id']
        super(QuantumRestProxyV2, self).delete_floatingip(context, id)

        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError:
            # TODO(Sumit): rollback deletion of floating IP
            raise

    def _send_all_data(self):
        """Pushes all data to network ctrl (networks/ports, ports/attachments)
        to give the controller an option to re-sync it's persistent store
        with quantum's current view of that data.
        """
        admin_context = qcontext.get_admin_context()
        networks = []
        routers = []

        all_networks = super(QuantumRestProxyV2,
                             self).get_networks(admin_context) or []
        for net in all_networks:
            mapped_network = self._get_mapped_network_with_subnets(net)
            net_fl_ips = self._get_network_with_floatingips(mapped_network)

            ports = []
            net_filter = {'network_id': [net.get('id')]}
            net_ports = super(QuantumRestProxyV2,
                              self).get_ports(admin_context,
                                              filters=net_filter) or []
            for port in net_ports:
                mapped_port = self._map_state_and_status(port)
                mapped_port['attachment'] = {
                    'id': port.get('device_id'),
                    'mac': port.get('mac_address'),
                }
                ports.append(mapped_port)
            net_fl_ips['ports'] = ports

            networks.append(net_fl_ips)

        all_routers = super(QuantumRestProxyV2,
                            self).get_routers(admin_context) or []
        for router in all_routers:
            interfaces = []
            mapped_router = self._map_state_and_status(router)
            router_filter = {
                'device_owner': ["network:router_interface"],
                'device_id': [router.get('id')]
            }
            router_ports = super(QuantumRestProxyV2,
                                 self).get_ports(admin_context,
                                                 filters=router_filter) or []
            for port in router_ports:
                net_id = port.get('network_id')
                subnet_id = port['fixed_ips'][0]['subnet_id']
                intf_details = self._get_router_intf_details(admin_context,
                                                             net_id,
                                                             subnet_id)
                interfaces.append(intf_details)
            mapped_router['interfaces'] = interfaces

            routers.append(mapped_router)

        try:
            resource = '/topology'
            data = {
                'networks': networks,
                'routers': routers,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            return ret
        except RemoteRestError as e:
            LOG.error(_('QuantumRestProxy: Unable to update remote '
                        'topology: %s'), e.message)
            raise

    def _add_host_route(self, context, destination, port):
        subnet = {}
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            nexthop = fixed_ip['ip_address']
            subnet['host_routes'] = [{'destination': destination,
                                      'nexthop': nexthop}]
            updated_subnet = self.update_subnet(context,
                                                subnet_id,
                                                {'subnet': subnet})
            payload = {'subnet': updated_subnet}
            self._dhcp_agent_notifier.notify(context, payload,
                                             'subnet.update.end')
            LOG.debug("Adding host route: ")
            LOG.debug("destination:%s nexthop:%s" % (destination,
                                                     nexthop))

    def _get_network_with_floatingips(self, network):
        admin_context = qcontext.get_admin_context()

        net_id = network['id']
        net_filter = {'floating_network_id': [net_id]}
        fl_ips = super(QuantumRestProxyV2,
                       self).get_floatingips(admin_context,
                                             filters=net_filter) or []
        network['floatingips'] = fl_ips

        return network

    def _get_all_subnets_json_for_network(self, net_id):
        admin_context = qcontext.get_admin_context()
        subnets = self._get_subnets_by_network(admin_context,
                                               net_id)
        subnets_details = []
        if subnets:
            for subnet in subnets:
                subnet_dict = self._make_subnet_dict(subnet)
                mapped_subnet = self._map_state_and_status(subnet_dict)
                subnets_details.append(mapped_subnet)

        return subnets_details

    def _get_mapped_network_with_subnets(self, network):
        admin_context = qcontext.get_admin_context()
        network = self._map_state_and_status(network)
        subnets = self._get_all_subnets_json_for_network(network['id'])
        network['subnets'] = subnets
        for subnet in (subnets or []):
            if subnet['gateway_ip']:
                # FIX: For backward compatibility with wire protocol
                network['gateway'] = subnet['gateway_ip']
                break
        else:
            network['gateway'] = ''

        network[l3.EXTERNAL] = self._network_is_external(admin_context,
                                                         network['id'])

        return network

    def _send_update_network(self, network):
        net_id = network['id']
        tenant_id = network['tenant_id']
        # update network on network controller
        try:
            resource = NETWORKS_PATH % (tenant_id, net_id)
            mapped_network = self._get_mapped_network_with_subnets(network)
            net_fl_ips = self._get_network_with_floatingips(mapped_network)
            data = {
                "network": net_fl_ips,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(_("QuantumRestProxyV2: Unable to update remote "
                        "network: %s"), e.message)
            raise

    def _map_state_and_status(self, resource):
        resource = copy.copy(resource)

        resource['state'] = ('UP' if resource.pop('admin_state_up',
                                                  True) else 'DOWN')

        if 'status' in resource:
            del resource['status']

        return resource

    def _warn_on_state_status(self, resource):
        if resource.get('admin_state_up', True) is False:
            LOG.warning(_("Setting admin_state_up=False is not supported"
                          " in this plugin version. Ignoring setting for "
                          "resource: %s"), resource)

        if 'status' in resource:
            if resource['status'] is not const.NET_STATUS_ACTIVE:
                LOG.warning(_("Operational status is internally set by the"
                              " plugin. Ignoring setting status=%s."),
                            resource['status'])

    def _get_router_intf_details(self, context, intf_id, subnet_id):

        # we will use the network id as interface's id
        net_id = intf_id
        network = super(QuantumRestProxyV2, self).get_network(context,
                                                              net_id)
        subnet = super(QuantumRestProxyV2, self).get_subnet(context,
                                                            subnet_id)
        mapped_network = self._get_mapped_network_with_subnets(network)
        mapped_subnet = self._map_state_and_status(subnet)

        data = {
            'id': intf_id,
            "network": mapped_network,
            "subnet": mapped_subnet
        }

        return data

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _enforce_set_auth(self, context, resource, action):
        policy.enforce(context, action, resource)

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_OVS
            port[portbindings.CAPABILITIES] = {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}
        return port
