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
Neutron REST Proxy Plug-in for Big Switch and FloodLight Controllers.

NeutronRestProxy provides a generic neutron plugin that translates all plugin
function calls to equivalent authenticated REST calls to a set of redundant
external network controllers. It also keeps persistent store for all neutron
state to allow for re-sync of the external controller(s), if required.

The local state on the plugin also allows for local response and fast-fail
semantics where it can be determined based on the local persistent store.

Network controller specific code is decoupled from this plugin and expected
to reside on the controller itself (via the REST interface).

This allows for:
 - independent authentication and redundancy schemes between neutron and the
   network controller
 - independent upgrade/development cycles between neutron and the controller
   as it limits the proxy code upgrade requirement to neutron release cycle
   and the controller specific code upgrade requirement to controller code
 - ability to sync the controller with neutron for independent recovery/reset

External REST API used by proxy is the same API as defined for neutron (JSON
subset) with some additional parameters (gateway on network-create and macaddr
on port-attach) on an additional PUT to do a bulk dump of all persistent data.
"""

import base64
import copy
import httplib
import json
import socket

from oslo.config import cfg

from neutron.api import extensions as neutron_extensions
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import context as qcontext
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import l3_db
from neutron.extensions import external_net
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.plugins.bigswitch.db import porttracker_db
from neutron.plugins.bigswitch import extensions
from neutron.plugins.bigswitch import routerrule_db
from neutron.plugins.bigswitch.version import version_string_with_vcs

LOG = logging.getLogger(__name__)

restproxy_opts = [
    cfg.StrOpt('servers', default='localhost:8800',
               help=_("A comma separated list of BigSwitch or Floodlight "
                      "servers and port numbers. The plugin proxies the "
                      "requests to the BigSwitch/Floodlight server, "
                      "which performs the networking configuration. Note that "
                      "only one server is needed per deployment, but you may "
                      "wish to deploy multiple servers to support failover.")),
    cfg.StrOpt('server_auth', default=None, secret=True,
               help=_("The username and password for authenticating against "
                      " the BigSwitch or Floodlight controller.")),
    cfg.BoolOpt('server_ssl', default=False,
                help=_("If True, Use SSL when connecting to the BigSwitch or "
                       "Floodlight controller.")),
    cfg.BoolOpt('sync_data', default=False,
                help=_("Sync data on connect")),
    cfg.IntOpt('server_timeout', default=10,
               help=_("Maximum number of seconds to wait for proxy request "
                      "to connect and complete.")),
    cfg.StrOpt('neutron_id', default='neutron-' + utils.get_hostname(),
               deprecated_name='quantum_id',
               help=_("User defined identifier for this Neutron deployment")),
    cfg.BoolOpt('add_meta_server_route', default=True,
                help=_("Flag to decide if a route to the metadata server "
                       "should be injected into the VM")),
]


cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")

router_opts = [
    cfg.MultiStrOpt('tenant_default_router_rule', default=['*:any:any:permit'],
                    help=_("The default router rules installed in new tenant "
                           "routers. Repeat the config option for each rule. "
                           "Format is <tenant>:<source>:<destination>:<action>"
                           " Use an * to specify default for all tenants.")),
    cfg.IntOpt('max_router_rules', default=200,
               help=_("Maximum number of router rules")),
]

cfg.CONF.register_opts(router_opts, "ROUTER")

nova_opts = [
    cfg.StrOpt('vif_type', default='ovs',
               help=_("Virtual interface type to configure on "
                      "Nova compute nodes")),
]

# Each VIF Type can have a list of nova host IDs that are fixed to that type
for i in portbindings.VIF_TYPES:
    opt = cfg.ListOpt('node_override_vif_' + i, default=[],
                      help=_("Nova compute nodes to manually set VIF "
                             "type to %s") % i)
    nova_opts.append(opt)

# Add the vif types for reference later
nova_opts.append(cfg.ListOpt('vif_types',
                             default=portbindings.VIF_TYPES,
                             help=_('List of allowed vif_type values.')))

cfg.CONF.register_opts(nova_opts, "NOVA")


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
SYNTAX_ERROR_MESSAGE = _('Syntax error in server config file, aborting plugin')
BASE_URI = '/networkService/v1.1'
ORCHESTRATION_SERVICE_ID = 'Neutron v2.0'
METADATA_SERVER_IP = '169.254.169.254'


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
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()

    def rest_call(self, action, resource, data, headers):
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
        LOG.debug(_("ServerProxy: resource=%(resource)s, action=%(action)s, "
                    "data=%(data)r, headers=%(headers)r"),
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
        timeout = cfg.CONF.RESTPROXY.server_timeout
        if timeout is not None:
            self.timeout = timeout

        # validate config
        if not servers:
            raise cfg.Error(_('Servers not defined. Aborting plugin'))
        if any((len(spl) != 2) for spl in [sp.split(':', 1)
                                           for sp in servers.split(',')]):
            raise cfg.Error(_('Servers must be defined as <ip>:<port>'))
        self.servers = [
            self.server_proxy_for(server, int(port))
            for server, port in (s.rsplit(':', 1) for s in servers.split(','))
        ]
        LOG.debug(_("ServerPool: initialization done"))

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

    @utils.synchronized('bsn-rest-call', external=True)
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
            LOG.warning(_("No device attached to port %s. "
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
        self.rest_create_port(tenant_id, net_id, port)


class RpcProxy(dhcp_rpc_base.DhcpRpcCallbackMixin):

    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class NeutronRestProxyV2Base(db_base_plugin_v2.NeutronDbPluginV2,
                             external_net_db.External_net_db_mixin,
                             routerrule_db.RouterRule_db_mixin):

    supported_extension_aliases = ["binding"]
    servers = None

    def __init__(self, server_timeout=None):
        # This base class is not intended to be instantiated directly.
        # Extending class should set ServerPool.
        if not self.servers:
            LOG.warning(_("ServerPool not set!"))

    def _send_all_data(self, send_ports=True, send_floating_ips=True,
                       send_routers=True):
        """Pushes all data to network ctrl (networks/ports, ports/attachments).

        This gives the controller an option to re-sync it's persistent store
        with neutron's current view of that data.
        """
        admin_context = qcontext.get_admin_context()
        networks = []

        all_networks = self.get_networks(admin_context) or []
        for net in all_networks:
            mapped_network = self._get_mapped_network_with_subnets(net)
            flips_n_ports = {}
            if send_floating_ips:
                flips_n_ports = self._get_network_with_floatingips(
                    mapped_network)

            if send_ports:
                ports = []
                net_filter = {'network_id': [net.get('id')]}
                net_ports = self.get_ports(admin_context,
                                           filters=net_filter) or []
                for port in net_ports:
                    mapped_port = self._map_state_and_status(port)
                    mapped_port['attachment'] = {
                        'id': port.get('device_id'),
                        'mac': port.get('mac_address'),
                    }
                    mapped_port = self._extend_port_dict_binding(admin_context,
                                                                 mapped_port)
                    ports.append(mapped_port)
                flips_n_ports['ports'] = ports

            if flips_n_ports:
                networks.append(flips_n_ports)

        resource = '/topology'
        data = {
            'networks': networks,
        }

        if send_routers:
            routers = []
            all_routers = self.get_routers(admin_context) or []
            for router in all_routers:
                interfaces = []
                mapped_router = self._map_state_and_status(router)
                router_filter = {
                    'device_owner': ["network:router_interface"],
                    'device_id': [router.get('id')]
                }
                router_ports = self.get_ports(admin_context,
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

            data.update({'routers': routers})

        errstr = _("Unable to update remote topology: %s")
        return self.servers.rest_action('PUT', resource, data, errstr)

    def _get_network_with_floatingips(self, network, context=None):
        if context is None:
            context = qcontext.get_admin_context()

        net_id = network['id']
        net_filter = {'floating_network_id': [net_id]}
        fl_ips = self.get_floatingips(context,
                                      filters=net_filter) or []
        network['floatingips'] = fl_ips

        return network

    def _get_all_subnets_json_for_network(self, net_id, context=None):
        if context is None:
            context = qcontext.get_admin_context()
        # start a sub-transaction to avoid breaking parent transactions
        with context.session.begin(subtransactions=True):
            subnets = self._get_subnets_by_network(context,
                                                   net_id)
        subnets_details = []
        if subnets:
            for subnet in subnets:
                subnet_dict = self._make_subnet_dict(subnet)
                mapped_subnet = self._map_state_and_status(subnet_dict)
                subnets_details.append(mapped_subnet)

        return subnets_details

    def _get_mapped_network_with_subnets(self, network, context=None):
        # if context is not provided, admin context is used
        if context is None:
            context = qcontext.get_admin_context()
        network = self._map_state_and_status(network)
        subnets = self._get_all_subnets_json_for_network(network['id'],
                                                         context)
        network['subnets'] = subnets
        for subnet in (subnets or []):
            if subnet['gateway_ip']:
                # FIX: For backward compatibility with wire protocol
                network['gateway'] = subnet['gateway_ip']
                break
        else:
            network['gateway'] = ''
        network[external_net.EXTERNAL] = self._network_is_external(
            context, network['id'])
        # include ML2 segmentation types
        network['segmentation_types'] = getattr(self, "segmentation_types", "")
        return network

    def _send_create_network(self, network, context=None):
        tenant_id = network['tenant_id']
        mapped_network = self._get_mapped_network_with_subnets(network,
                                                               context)
        self.servers.rest_create_network(tenant_id, mapped_network)

    def _send_update_network(self, network, context=None):
        net_id = network['id']
        tenant_id = network['tenant_id']
        mapped_network = self._get_mapped_network_with_subnets(network,
                                                               context)
        net_fl_ips = self._get_network_with_floatingips(mapped_network,
                                                        context)
        self.servers.rest_update_network(tenant_id, net_id, net_fl_ips)

    def _send_delete_network(self, network, context=None):
        net_id = network['id']
        tenant_id = network['tenant_id']
        self.servers.rest_delete_network(tenant_id, net_id)

    def _map_state_and_status(self, resource):
        resource = copy.copy(resource)

        resource['state'] = ('UP' if resource.pop('admin_state_up',
                                                  True) else 'DOWN')

        if 'status' in resource:
            del resource['status']

        return resource

    def _warn_on_state_status(self, resource):
        if resource.get('admin_state_up', True) is False:
            LOG.warning(_("Setting admin_state_up=False is not supported "
                          "in this plugin version. Ignoring setting for "
                          "resource: %s"), resource)

        if 'status' in resource:
            if resource['status'] is not const.NET_STATUS_ACTIVE:
                LOG.warning(_("Operational status is internally set by the "
                              "plugin. Ignoring setting status=%s."),
                            resource['status'])

    def _get_router_intf_details(self, context, intf_id, subnet_id):

        # we will use the network id as interface's id
        net_id = intf_id
        network = self.get_network(context, net_id)
        subnet = self.get_subnet(context, subnet_id)
        mapped_network = self._get_mapped_network_with_subnets(network)
        mapped_subnet = self._map_state_and_status(subnet)

        data = {
            'id': intf_id,
            "network": mapped_network,
            "subnet": mapped_subnet
        }

        return data

    def _extend_port_dict_binding(self, context, port):
        cfg_vif_type = cfg.CONF.NOVA.vif_type.lower()
        if not cfg_vif_type in (portbindings.VIF_TYPE_OVS,
                                portbindings.VIF_TYPE_IVS):
            LOG.warning(_("Unrecognized vif_type in configuration "
                          "[%s]. Defaulting to ovs."),
                        cfg_vif_type)
            cfg_vif_type = portbindings.VIF_TYPE_OVS
        hostid = porttracker_db.get_port_hostid(context, port['id'])
        if hostid:
            port[portbindings.HOST_ID] = hostid
            override = self._check_hostvif_override(hostid)
            if override:
                cfg_vif_type = override
        port[portbindings.VIF_TYPE] = cfg_vif_type

        port[portbindings.CAPABILITIES] = {
            portbindings.CAP_PORT_FILTER:
            'security-group' in self.supported_extension_aliases}
        return port

    def _check_hostvif_override(self, hostid):
        for v in cfg.CONF.NOVA.vif_types:
            if hostid in getattr(cfg.CONF.NOVA, "node_override_vif_" + v, []):
                return v
        return False


class NeutronRestProxyV2(NeutronRestProxyV2Base,
                         extradhcpopt_db.ExtraDhcpOptMixin,
                         agentschedulers_db.DhcpAgentSchedulerDbMixin):

    supported_extension_aliases = ["external-net", "router", "binding",
                                   "router_rules", "extra_dhcp_opt", "quotas",
                                   "dhcp_agent_scheduler", "agent"]

    def __init__(self, server_timeout=None):
        LOG.info(_('NeutronRestProxy: Starting plugin. Version=%s'),
                 version_string_with_vcs())

        # init DB, proxy's persistent store defaults to in-memory sql-lite DB
        db.configure_db()

        # Include the BigSwitch Extensions path in the api_extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)

        self.add_meta_server_route = cfg.CONF.RESTPROXY.add_meta_server_route

        # init network ctrl connections
        self.servers = ServerPool(server_timeout, BASE_URI)

        # init dhcp support
        self.topic = topics.PLUGIN
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self._dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            self._dhcp_agent_notifier
        )
        self.conn = rpc.create_connection(new=True)
        self.callbacks = RpcProxy()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        if cfg.CONF.RESTPROXY.sync_data:
            self._send_all_data()

        LOG.debug(_("NeutronRestProxyV2: initialization done"))

    def create_network(self, context, network):
        """Create a network.

        Network represents an L2 network segment which can have a set of
        subnets and ports associated with it.

        :param context: neutron api request context
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
        LOG.debug(_("NeutronRestProxyV2: create_network() called"))

        self._warn_on_state_status(network['network'])

        with context.session.begin(subtransactions=True):
            # create network in DB
            new_net = super(NeutronRestProxyV2, self).create_network(context,
                                                                     network)
            self._process_l3_create(context, new_net, network['network'])
            # create network on the network controller
            self._send_create_network(new_net, context)

        # return created network
        return new_net

    def update_network(self, context, net_id, network):
        """Updates the properties of a particular Virtual Network.

        :param context: neutron api request context
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
        LOG.debug(_("NeutronRestProxyV2.update_network() called"))

        self._warn_on_state_status(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            new_net = super(NeutronRestProxyV2, self).update_network(
                context, net_id, network)
            self._process_l3_update(context, new_net, network['network'])

            # update network on network controller
            self._send_update_network(new_net, context)
        return new_net

    def delete_network(self, context, net_id):
        """Delete a network.
        :param context: neutron api request context
        :param id: UUID representing the network to delete.

        :returns: None

        :raises: exceptions.NetworkInUse
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug(_("NeutronRestProxyV2: delete_network() called"))

        # Validate args
        orig_net = super(NeutronRestProxyV2, self).get_network(context, net_id)

        filter = {'network_id': [net_id]}
        ports = self.get_ports(context, filters=filter)

        # check if there are any tenant owned ports in-use
        auto_delete_port_owners = db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
        only_auto_del = all(p['device_owner'] in auto_delete_port_owners
                            for p in ports)

        if not only_auto_del:
            raise exceptions.NetworkInUse(net_id=net_id)
        with context.session.begin(subtransactions=True):
            ret_val = super(NeutronRestProxyV2, self).delete_network(context,
                                                                     net_id)
            self._send_delete_network(orig_net, context)
            return ret_val

    def create_port(self, context, port):
        """Create a port, which is a connection point of a device
        (e.g., a VM NIC) to attach to a L2 Neutron network.
        :param context: neutron api request context
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
        LOG.debug(_("NeutronRestProxyV2: create_port() called"))

        # Update DB in new session so exceptions rollback changes
        with context.session.begin(subtransactions=True):
            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            new_port = super(NeutronRestProxyV2, self).create_port(context,
                                                                   port)
            if (portbindings.HOST_ID in port['port']
                and 'id' in new_port):
                host_id = port['port'][portbindings.HOST_ID]
                porttracker_db.put_port_hostid(context, new_port['id'],
                                               host_id)
            self._process_port_create_extra_dhcp_opts(context, new_port,
                                                      dhcp_opts)
            new_port = self._extend_port_dict_binding(context, new_port)
            net = super(NeutronRestProxyV2,
                        self).get_network(context, new_port["network_id"])
            if self.add_meta_server_route:
                if new_port['device_owner'] == 'network:dhcp':
                    destination = METADATA_SERVER_IP + '/32'
                    self._add_host_route(context, destination, new_port)

            # create on network ctrl
            mapped_port = self._map_state_and_status(new_port)
            self.servers.rest_create_port(net["tenant_id"],
                                          new_port["network_id"],
                                          mapped_port)
        return new_port

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(NeutronRestProxyV2, self).get_port(context, id,
                                                            fields)
            self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports = super(NeutronRestProxyV2, self).get_ports(context, filters,
                                                              fields)
            for port in ports:
                self._extend_port_dict_binding(context, port)
        return [self._fields(port, fields) for port in ports]

    def update_port(self, context, port_id, port):
        """Update values of a port.

        :param context: neutron api request context
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
        LOG.debug(_("NeutronRestProxyV2: update_port() called"))

        self._warn_on_state_status(port['port'])

        # Validate Args
        orig_port = super(NeutronRestProxyV2, self).get_port(context, port_id)
        with context.session.begin(subtransactions=True):
            # Update DB
            new_port = super(NeutronRestProxyV2,
                             self).update_port(context, port_id, port)
            self._update_extra_dhcp_opts_on_port(context, port_id, port,
                                                 new_port)
            ctrl_update_required = False
            old_host_id = porttracker_db.get_port_hostid(context,
                                                         orig_port['id'])
            if (portbindings.HOST_ID in port['port']
                and 'id' in new_port):
                host_id = port['port'][portbindings.HOST_ID]
                porttracker_db.put_port_hostid(context, new_port['id'],
                                               host_id)
                if old_host_id != host_id:
                    ctrl_update_required = True

            if (new_port.get("device_id") != orig_port.get("device_id") and
                orig_port.get("device_id")):
                ctrl_update_required = True

            if ctrl_update_required:
                new_port = self._extend_port_dict_binding(context, new_port)
                mapped_port = self._map_state_and_status(new_port)
                self.servers.rest_update_port(new_port["tenant_id"],
                                              new_port["network_id"],
                                              mapped_port)

        # return new_port
        return new_port

    def delete_port(self, context, port_id, l3_port_check=True):
        """Delete a port.

        :param context: neutron api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug(_("NeutronRestProxyV2: delete_port() called"))

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, port_id)
            super(NeutronRestProxyV2, self).delete_port(context, port_id)

    def _delete_port(self, context, port_id):
        port = super(NeutronRestProxyV2, self).get_port(context, port_id)
        tenant_id = port['tenant_id']
        net_id = port['network_id']
        if tenant_id == '':
            net = super(NeutronRestProxyV2, self).get_network(context, net_id)
            tenant_id = net['tenant_id']
        # Delete from DB
        ret_val = super(NeutronRestProxyV2,
                        self)._delete_port(context, port_id)
        self.servers.rest_delete_port(tenant_id, net_id, port_id)
        return ret_val

    def create_subnet(self, context, subnet):
        LOG.debug(_("NeutronRestProxyV2: create_subnet() called"))

        self._warn_on_state_status(subnet['subnet'])

        with context.session.begin(subtransactions=True):
            # create subnet in DB
            new_subnet = super(NeutronRestProxyV2,
                               self).create_subnet(context, subnet)
            net_id = new_subnet['network_id']
            orig_net = super(NeutronRestProxyV2,
                             self).get_network(context, net_id)
            # update network on network controller
            self._send_update_network(orig_net, context)
        return new_subnet

    def update_subnet(self, context, id, subnet):
        LOG.debug(_("NeutronRestProxyV2: update_subnet() called"))

        self._warn_on_state_status(subnet['subnet'])

        with context.session.begin(subtransactions=True):
            # update subnet in DB
            new_subnet = super(NeutronRestProxyV2,
                               self).update_subnet(context, id, subnet)
            net_id = new_subnet['network_id']
            orig_net = super(NeutronRestProxyV2,
                             self).get_network(context, net_id)
            # update network on network controller
            self._send_update_network(orig_net, context)
            return new_subnet

    def delete_subnet(self, context, id):
        LOG.debug(_("NeutronRestProxyV2: delete_subnet() called"))
        orig_subnet = super(NeutronRestProxyV2, self).get_subnet(context, id)
        net_id = orig_subnet['network_id']
        with context.session.begin(subtransactions=True):
            # delete subnet in DB
            super(NeutronRestProxyV2, self).delete_subnet(context, id)
            orig_net = super(NeutronRestProxyV2, self).get_network(context,
                                                                   net_id)
            # update network on network controller - exception will rollback
            self._send_update_network(orig_net, context)

    def _get_tenant_default_router_rules(self, tenant):
        rules = cfg.CONF.ROUTER.tenant_default_router_rule
        defaultset = []
        tenantset = []
        for rule in rules:
            items = rule.split(':')
            if len(items) == 5:
                (tenantid, source, destination, action, nexthops) = items
            elif len(items) == 4:
                (tenantid, source, destination, action) = items
                nexthops = ''
            else:
                continue
            parsedrule = {'source': source,
                          'destination': destination, 'action': action,
                          'nexthops': nexthops.split(',')}
            if parsedrule['nexthops'][0] == '':
                parsedrule['nexthops'] = []
            if tenantid == '*':
                defaultset.append(parsedrule)
            if tenantid == tenant:
                tenantset.append(parsedrule)
        if tenantset:
            return tenantset
        return defaultset

    def create_router(self, context, router):
        LOG.debug(_("NeutronRestProxyV2: create_router() called"))

        self._warn_on_state_status(router['router'])

        tenant_id = self._get_tenant_id_for_create(context, router["router"])

        # set default router rules
        rules = self._get_tenant_default_router_rules(tenant_id)
        router['router']['router_rules'] = rules

        with context.session.begin(subtransactions=True):
            # create router in DB
            new_router = super(NeutronRestProxyV2, self).create_router(context,
                                                                       router)
            mapped_router = self._map_state_and_status(new_router)
            self.servers.rest_create_router(tenant_id, mapped_router)

            # return created router
            return new_router

    def update_router(self, context, router_id, router):

        LOG.debug(_("NeutronRestProxyV2.update_router() called"))

        self._warn_on_state_status(router['router'])

        orig_router = super(NeutronRestProxyV2, self).get_router(context,
                                                                 router_id)
        tenant_id = orig_router["tenant_id"]
        with context.session.begin(subtransactions=True):
            new_router = super(NeutronRestProxyV2,
                               self).update_router(context, router_id, router)
            router = self._map_state_and_status(new_router)

            # update router on network controller
            self.servers.rest_update_router(tenant_id, router, router_id)

            # return updated router
            return new_router

    def delete_router(self, context, router_id):
        LOG.debug(_("NeutronRestProxyV2: delete_router() called"))

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
            ret_val = super(NeutronRestProxyV2,
                            self).delete_router(context, router_id)

            # delete from network ctrl
            self.servers.rest_delete_router(tenant_id, router_id)
            return ret_val

    def add_router_interface(self, context, router_id, interface_info):

        LOG.debug(_("NeutronRestProxyV2: add_router_interface() called"))

        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        with context.session.begin(subtransactions=True):
            # create interface in DB
            new_intf_info = super(NeutronRestProxyV2,
                                  self).add_router_interface(context,
                                                             router_id,
                                                             interface_info)
            port = self._get_port(context, new_intf_info['port_id'])
            net_id = port['network_id']
            subnet_id = new_intf_info['subnet_id']
            # we will use the port's network id as interface's id
            interface_id = net_id
            intf_details = self._get_router_intf_details(context,
                                                         interface_id,
                                                         subnet_id)

            # create interface on the network controller
            self.servers.rest_add_router_interface(tenant_id, router_id,
                                                   intf_details)
            return new_intf_info

    def remove_router_interface(self, context, router_id, interface_info):

        LOG.debug(_("NeutronRestProxyV2: remove_router_interface() called"))

        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # we will first get the interface identifier before deleting in the DB
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port = self._get_port(context, interface_info['port_id'])
            interface_id = port['network_id']
        elif 'subnet_id' in interface_info:
            subnet = self._get_subnet(context, interface_info['subnet_id'])
            interface_id = subnet['network_id']
        else:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)

        with context.session.begin(subtransactions=True):
            # remove router in DB
            del_ret = super(NeutronRestProxyV2,
                            self).remove_router_interface(context,
                                                          router_id,
                                                          interface_info)

            # create router on the network controller
            self.servers.rest_remove_router_interface(tenant_id, router_id,
                                                      interface_id)
            return del_ret

    def create_floatingip(self, context, floatingip):
        LOG.debug(_("NeutronRestProxyV2: create_floatingip() called"))

        with context.session.begin(subtransactions=True):
            # create floatingip in DB
            new_fl_ip = super(NeutronRestProxyV2,
                              self).create_floatingip(context, floatingip)

            # create floatingip on the network controller
            try:
                self._send_floatingip_update(context)
            except RemoteRestError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        _("NeutronRestProxyV2: Unable to create remote "
                          "floating IP: %s"), e)
            # return created floating IP
            return new_fl_ip

    def update_floatingip(self, context, id, floatingip):
        LOG.debug(_("NeutronRestProxyV2: update_floatingip() called"))

        with context.session.begin(subtransactions=True):
            # update floatingip in DB
            new_fl_ip = super(NeutronRestProxyV2,
                              self).update_floatingip(context, id, floatingip)

            # update network on network controller
            self._send_floatingip_update(context)
            return new_fl_ip

    def delete_floatingip(self, context, id):
        LOG.debug(_("NeutronRestProxyV2: delete_floatingip() called"))

        with context.session.begin(subtransactions=True):
            # delete floating IP in DB
            super(NeutronRestProxyV2, self).delete_floatingip(context, id)

            # update network on network controller
            self._send_floatingip_update(context)

    def disassociate_floatingips(self, context, port_id):
        LOG.debug(_("NeutronRestProxyV2: diassociate_floatingips() called"))
        super(NeutronRestProxyV2, self).disassociate_floatingips(context,
                                                                 port_id)
        self._send_floatingip_update(context)

    def _send_floatingip_update(self, context):
        try:
            ext_net_id = self.get_external_network_id(context)
            if ext_net_id:
                # Use the elevated state of the context for the ext_net query
                admin_context = context.elevated()
                ext_net = super(NeutronRestProxyV2,
                                self).get_network(admin_context, ext_net_id)
                # update external network on network controller
                self._send_update_network(ext_net, admin_context)
        except exceptions.TooManyExternalNetworks:
            # get_external_network can raise errors when multiple external
            # networks are detected, which isn't supported by the Plugin
            LOG.error(_("NeutronRestProxyV2: too many external networks"))

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
            LOG.debug(_("Adding host route: "))
            LOG.debug(_("Destination:%(dst)s nexthop:%(next)s"),
                      {'dst': destination, 'next': nexthop})
