# Copyright 2012 VMware, Inc.  All rights reserved.
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

import eventlet
import netaddr
from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import ovs_lib  # noqa
from neutron.agent import rpc as agent_rpc
from neutron.common import constants as l3_constants
from neutron.common import legacy
from neutron.common import topics
from neutron.common import utils as common_utils
from neutron import context
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.openstack.common import processutils
from neutron.openstack.common.rpc import common as rpc_common
from neutron.openstack.common.rpc import proxy
from neutron.openstack.common import service
from neutron import service as neutron_service
from neutron.services.firewall.agents.l3reference import firewall_l3_agent

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
INTERNAL_DEV_PREFIX = 'qr-'
EXTERNAL_DEV_PREFIX = 'qg-'
RPC_LOOP_INTERVAL = 1
FLOATING_IP_CIDR_SUFFIX = '/32'


class L3PluginApi(proxy.RpcProxy):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.
        1.1 - Floating IP operational status updates

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(L3PluginApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.host = host

    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        return self.call(context,
                         self.make_msg('sync_routers', host=self.host,
                                       router_ids=router_ids),
                         topic=self.topic)

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        @raise common.RemoteError: with TooManyExternalNetworks
                                   as exc_type if there are
                                   more than one external network
        """
        return self.call(context,
                         self.make_msg('get_external_network_id',
                                       host=self.host),
                         topic=self.topic)

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Call the plugin update floating IPs's operational status."""
        return self.call(context,
                         self.make_msg('update_floatingip_statuses',
                                       router_id=router_id,
                                       fip_statuses=fip_statuses),
                         topic=self.topic,
                         version='1.1')


class RouterInfo(object):

    def __init__(self, router_id, root_helper, use_namespaces, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.floating_ips = set()
        self.root_helper = root_helper
        self.use_namespaces = use_namespaces
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.ns_name = NS_PREFIX + router_id if use_namespaces else None
        self.iptables_manager = iptables_manager.IptablesManager(
            root_helper=root_helper,
            #FIXME(danwent): use_ipv6=True,
            namespace=self.ns_name)
        self.routes = []

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'

    def perform_snat_action(self, snat_callback, *args):
        # Process SNAT rules for attached subnets
        if self._snat_action:
            snat_callback(self, self._router.get('gw_port'),
                          *args, action=self._snat_action)
        self._snat_action = None


class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback, manager.Manager):
    """Manager for L3NatAgent

        API version history:
        1.0 initial Version
        1.1 changed the type of the routers parameter
            to the routers_updated method.
            It was previously a list of routers in dict format.
            It is now a list of router IDs only.
            Per rpc versioning rules,  it is backwards compatible.
    """
    RPC_API_VERSION = '1.1'

    OPTS = [
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help=_("Name of bridge used for external network "
                          "traffic.")),
        cfg.IntOpt('metadata_port',
                   default=9697,
                   help=_("TCP Port used by Neutron metadata namespace "
                          "proxy.")),
        cfg.IntOpt('send_arp_for_ha',
                   default=0,
                   help=_("Send this many gratuitous ARPs for HA setup, if "
                          "less than or equal to 0, the feature is disabled")),
        cfg.StrOpt('router_id', default='',
                   help=_("If namespaces is disabled, the l3 agent can only"
                          " configure a router that has the matching router "
                          "ID.")),
        cfg.BoolOpt('handle_internal_only_routers',
                    default=True,
                    help=_("Agent should implement routers with no gateway")),
        cfg.StrOpt('gateway_external_network_id', default='',
                   help=_("UUID of external network for routers implemented "
                          "by the agents.")),
        cfg.BoolOpt('enable_metadata_proxy', default=True,
                    help=_("Allow running metadata proxy.")),
        cfg.BoolOpt('router_delete_namespaces', default=False,
                    help=_("Delete namespace after removing a router.")),
        cfg.StrOpt('metadata_proxy_socket',
                   default='$state_path/metadata_proxy',
                   help=_('Location of Metadata Proxy UNIX domain '
                          'socket')),
    ]

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.router_info = {}

        self._check_config_params()

        try:
            self.driver = importutils.import_object(
                self.conf.interface_driver,
                self.conf
            )
        except Exception:
            msg = _("Error importing interface driver "
                    "'%s'") % self.conf.interface_driver
            LOG.error(msg)
            raise SystemExit(msg)

        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, host)
        self.fullsync = True
        self.updated_routers = set()
        self.removed_routers = set()
        self.sync_progress = False

        self._delete_stale_namespaces = (self.conf.use_namespaces and
                                         self.conf.router_delete_namespaces)

        self.rpc_loop = loopingcall.FixedIntervalLoopingCall(
            self._rpc_loop)
        self.rpc_loop.start(interval=RPC_LOOP_INTERVAL)
        super(L3NATAgent, self).__init__(conf=self.conf)

        self.target_ex_net_id = None

    def _check_config_params(self):
        """Check items in configuration files.

        Check for required and invalid configuration items.
        The actual values are not verified for correctness.
        """
        if not self.conf.interface_driver:
            msg = _('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(msg)

        if not self.conf.use_namespaces and not self.conf.router_id:
            msg = _('Router id is required if not using namespaces.')
            LOG.error(msg)
            raise SystemExit(msg)

    def _cleanup_namespaces(self, routers):
        """Destroy stale router namespaces on host when L3 agent restarts

        This routine is called when self._delete_stale_namespaces is True.

        The argument routers is the list of routers that are recorded in
        the database as being hosted on this node.
        """
        try:
            root_ip = ip_lib.IPWrapper(self.root_helper)

            host_namespaces = root_ip.get_namespaces(self.root_helper)
            router_namespaces = set(ns for ns in host_namespaces
                                    if ns.startswith(NS_PREFIX))
            ns_to_ignore = set(NS_PREFIX + r['id'] for r in routers)
            ns_to_destroy = router_namespaces - ns_to_ignore
        except RuntimeError:
            LOG.exception(_('RuntimeError in obtaining router list '
                            'for namespace cleanup.'))
        else:
            self._destroy_stale_router_namespaces(ns_to_destroy)

    def _destroy_stale_router_namespaces(self, router_namespaces):
        """Destroys the stale router namespaces

        The argumenet router_namespaces is a list of stale router namespaces

        As some stale router namespaces may not be able to be deleted, only
        one attempt will be made to delete them.
        """
        for ns in router_namespaces:
            if self.conf.enable_metadata_proxy:
                self._destroy_metadata_proxy(ns[len(NS_PREFIX):], ns)

            try:
                self._destroy_router_namespace(ns)
            except RuntimeError:
                LOG.exception(_('Failed to destroy stale router namespace '
                                '%s'), ns)
        self._delete_stale_namespaces = False

    def _destroy_router_namespace(self, namespace):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=namespace)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(INTERNAL_DEV_PREFIX):
                # device is on default bridge
                self.driver.unplug(d.name, namespace=namespace,
                                   prefix=INTERNAL_DEV_PREFIX)
            elif d.name.startswith(EXTERNAL_DEV_PREFIX):
                self.driver.unplug(d.name,
                                   bridge=self.conf.external_network_bridge,
                                   namespace=namespace,
                                   prefix=EXTERNAL_DEV_PREFIX)

        if self.conf.router_delete_namespaces:
            try:
                ns_ip.netns.delete(namespace)
            except RuntimeError:
                msg = _('Failed trying to delete namespace: %s')
                LOG.exception(msg % namespace)

    def _create_router_namespace(self, ri):
            ip_wrapper_root = ip_lib.IPWrapper(self.root_helper)
            ip_wrapper = ip_wrapper_root.ensure_namespace(ri.ns_name)
            ip_wrapper.netns.execute(['sysctl', '-w', 'net.ipv4.ip_forward=1'])

    def _fetch_external_net_id(self, force=False):
        """Find UUID of single external network for this agent."""
        if self.conf.gateway_external_network_id:
            return self.conf.gateway_external_network_id

        # L3 agent doesn't use external_network_bridge to handle external
        # networks, so bridge_mappings with provider networks will be used
        # and the L3 agent is able to handle any external networks.
        if not self.conf.external_network_bridge:
            return

        if not force and self.target_ex_net_id:
            return self.target_ex_net_id

        try:
            self.target_ex_net_id = self.plugin_rpc.get_external_network_id(
                self.context)
            return self.target_ex_net_id
        except rpc_common.RemoteError as e:
            with excutils.save_and_reraise_exception() as ctx:
                if e.exc_type == 'TooManyExternalNetworks':
                    ctx.reraise = False
                    msg = _(
                        "The 'gateway_external_network_id' option must be "
                        "configured for this agent as Neutron has more than "
                        "one external network.")
                    raise Exception(msg)

    def _router_added(self, router_id, router):
        ri = RouterInfo(router_id, self.root_helper,
                        self.conf.use_namespaces, router)
        self.router_info[router_id] = ri
        if self.conf.use_namespaces:
            self._create_router_namespace(ri)
        for c, r in self.metadata_filter_rules():
            ri.iptables_manager.ipv4['filter'].add_rule(c, r)
        for c, r in self.metadata_nat_rules():
            ri.iptables_manager.ipv4['nat'].add_rule(c, r)
        ri.iptables_manager.apply()
        super(L3NATAgent, self).process_router_add(ri)
        if self.conf.enable_metadata_proxy:
            self._spawn_metadata_proxy(ri.router_id, ri.ns_name)

    def _router_removed(self, router_id):
        ri = self.router_info.get(router_id)
        if ri is None:
            LOG.warn(_("Info for router %s were not found. "
                       "Skipping router removal"), router_id)
            return
        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        self.process_router(ri)
        for c, r in self.metadata_filter_rules():
            ri.iptables_manager.ipv4['filter'].remove_rule(c, r)
        for c, r in self.metadata_nat_rules():
            ri.iptables_manager.ipv4['nat'].remove_rule(c, r)
        ri.iptables_manager.apply()
        if self.conf.enable_metadata_proxy:
            self._destroy_metadata_proxy(ri.router_id, ri.ns_name)
        del self.router_info[router_id]
        self._destroy_router_namespace(ri.ns_name)

    def _spawn_metadata_proxy(self, router_id, ns_name):
        def callback(pid_file):
            metadata_proxy_socket = cfg.CONF.metadata_proxy_socket
            proxy_cmd = ['neutron-ns-metadata-proxy',
                         '--pid_file=%s' % pid_file,
                         '--metadata_proxy_socket=%s' % metadata_proxy_socket,
                         '--router_id=%s' % router_id,
                         '--state_path=%s' % self.conf.state_path,
                         '--metadata_port=%s' % self.conf.metadata_port]
            proxy_cmd.extend(config.get_log_args(
                cfg.CONF, 'neutron-ns-metadata-proxy-%s.log' %
                router_id))
            return proxy_cmd

        pm = external_process.ProcessManager(
            self.conf,
            router_id,
            self.root_helper,
            ns_name)
        pm.enable(callback)

    def _destroy_metadata_proxy(self, router_id, ns_name):
        pm = external_process.ProcessManager(
            self.conf,
            router_id,
            self.root_helper,
            ns_name)
        pm.disable()

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def _get_existing_devices(self, ri):
        ip_wrapper = ip_lib.IPWrapper(root_helper=self.root_helper,
                                      namespace=ri.ns_name)
        ip_devs = ip_wrapper.get_devices(exclude_loopback=True)
        return [ip_dev.name for ip_dev in ip_devs]

    def process_router(self, ri):
        ri.iptables_manager.defer_apply_on()
        ex_gw_port = self._get_ex_gw_port(ri)
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]
        for p in new_ports:
            self._set_subnet_info(p)
            self.internal_network_added(ri, p['network_id'], p['id'],
                                        p['ip_cidr'], p['mac_address'])
            ri.internal_ports.append(p)

        for p in old_ports:
            self.internal_network_removed(ri, p['id'], p['ip_cidr'])
            ri.internal_ports.remove(p)

        existing_devices = self._get_existing_devices(ri)
        current_internal_devs = set([n for n in existing_devices
                                     if n.startswith(INTERNAL_DEV_PREFIX)])
        current_port_devs = set([self.get_internal_device_name(id) for
                                 id in current_port_ids])
        stale_devs = current_internal_devs - current_port_devs
        for stale_dev in stale_devs:
            LOG.debug(_('Deleting stale internal router device: %s'),
                      stale_dev)
            self.driver.unplug(stale_dev,
                               namespace=ri.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

        # Get IPv4 only internal CIDRs
        internal_cidrs = [p['ip_cidr'] for p in ri.internal_ports
                          if netaddr.IPNetwork(p['ip_cidr']).version == 4]
        # TODO(salv-orlando): RouterInfo would be a better place for
        # this logic too
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                         ri.ex_gw_port and ri.ex_gw_port['id'])

        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port and not ri.ex_gw_port:
            self._set_subnet_info(ex_gw_port)
            self.external_gateway_added(ri, ex_gw_port,
                                        interface_name, internal_cidrs)
        elif not ex_gw_port and ri.ex_gw_port:
            self.external_gateway_removed(ri, ri.ex_gw_port,
                                          interface_name, internal_cidrs)

        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX)
                      and dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug(_('Deleting stale external router device: %s'),
                      stale_dev)
            self.driver.unplug(stale_dev,
                               bridge=self.conf.external_network_bridge,
                               namespace=ri.ns_name,
                               prefix=EXTERNAL_DEV_PREFIX)

        # Process static routes for router
        self.routes_updated(ri)
        # Process SNAT rules for external gateway
        ri.perform_snat_action(self._handle_router_snat_rules,
                               internal_cidrs, interface_name)

        # Process SNAT/DNAT rules for floating IPs
        fip_statuses = {}
        try:
            if ex_gw_port:
                existing_floating_ips = ri.floating_ips
                self.process_router_floating_ip_nat_rules(ri)
                ri.iptables_manager.defer_apply_off()
                # Once NAT rules for floating IPs are safely in place
                # configure their addresses on the external gateway port
                fip_statuses = self.process_router_floating_ip_addresses(
                    ri, ex_gw_port)
        except Exception:
            # TODO(salv-orlando): Less broad catching
            # All floating IPs must be put in error state
            for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
                fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR

        if ex_gw_port:
            # Identify floating IPs which were disabled
            ri.floating_ips = set(fip_statuses.keys())
            for fip_id in existing_floating_ips - ri.floating_ips:
                fip_statuses[fip_id] = l3_constants.FLOATINGIP_STATUS_DOWN
            # Update floating IP status on the neutron server
            self.plugin_rpc.update_floatingip_statuses(
                self.context, ri.router_id, fip_statuses)

        # Update ex_gw_port and enable_snat on the router info cache
        ri.ex_gw_port = ex_gw_port
        ri.enable_snat = ri.router.get('enable_snat')

    def _handle_router_snat_rules(self, ri, ex_gw_port, internal_cidrs,
                                  interface_name, action):
        # Remove all the rules
        # This is safe because if use_namespaces is set as False
        # then the agent can only configure one router, otherwise
        # each router's SNAT rules will be in their own namespace
        ri.iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        ri.iptables_manager.ipv4['nat'].empty_chain('snat')

        # Add back the jump to float-snat
        ri.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        # And add them back if the action if add_rules
        if action == 'add_rules' and ex_gw_port:
            # ex_gw_port should not be None in this case
            # NAT rules are added only if ex_gw_port has an IPv4 address
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                if netaddr.IPAddress(ex_gw_ip).version == 4:
                    rules = self.external_gateway_nat_rules(ex_gw_ip,
                                                            internal_cidrs,
                                                            interface_name)
                    for rule in rules:
                        ri.iptables_manager.ipv4['nat'].add_rule(*rule)
                    break
        ri.iptables_manager.apply()

    def process_router_floating_ip_nat_rules(self, ri):
        """Configure NAT rules for the router's floating IPs.

        Configures iptables rules for the floating ips of the given router
        """
        # Clear out all iptables rules for floating ips
        ri.iptables_manager.ipv4['nat'].clear_rules_by_tag('floating_ip')

        # Loop once to ensure that floating ips are configured.
        for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
            # Rebuild iptables rules for the floating ip.
            fixed = fip['fixed_ip_address']
            fip_ip = fip['floating_ip_address']
            for chain, rule in self.floating_forward_rules(fip_ip, fixed):
                ri.iptables_manager.ipv4['nat'].add_rule(chain, rule,
                                                         tag='floating_ip')

        ri.iptables_manager.apply()

    def process_router_floating_ip_addresses(self, ri, ex_gw_port):
        """Configure IP addresses on router's external gateway interface.

        Ensures addresses for existing floating IPs and cleans up
        those that should not longer be configured.
        """
        fip_statuses = {}
        interface_name = self.get_external_device_name(ex_gw_port['id'])
        device = ip_lib.IPDevice(interface_name, self.root_helper,
                                 namespace=ri.ns_name)
        existing_cidrs = set([addr['cidr'] for addr in device.addr.list()])
        new_cidrs = set()

        # Loop once to ensure that floating ips are configured.
        for fip in ri.router.get(l3_constants.FLOATINGIP_KEY, []):
            fip_ip = fip['floating_ip_address']
            ip_cidr = str(fip_ip) + FLOATING_IP_CIDR_SUFFIX

            new_cidrs.add(ip_cidr)

            if ip_cidr not in existing_cidrs:
                net = netaddr.IPNetwork(ip_cidr)
                try:
                    device.addr.add(net.version, ip_cidr, str(net.broadcast))
                except (processutils.UnknownArgumentError,
                        processutils.ProcessExecutionError):
                    # any exception occurred here should cause the floating IP
                    # to be set in error state
                    fip_statuses[fip['id']] = (
                        l3_constants.FLOATINGIP_STATUS_ERROR)
                    LOG.warn(_("Unable to configure IP address for "
                               "floating IP: %s"), fip['id'])
                    continue
                # As GARP is processed in a distinct thread the call below
                # won't raise an exception to be handled.
                self._send_gratuitous_arp_packet(
                    ri, interface_name, fip_ip)
            fip_statuses[fip['id']] = (
                l3_constants.FLOATINGIP_STATUS_ACTIVE)

        # Clean up addresses that no longer belong on the gateway interface.
        for ip_cidr in existing_cidrs - new_cidrs:
            if ip_cidr.endswith(FLOATING_IP_CIDR_SUFFIX):
                net = netaddr.IPNetwork(ip_cidr)
                device.addr.delete(net.version, ip_cidr)
        return fip_statuses

    def _get_ex_gw_port(self, ri):
        return ri.router.get('gw_port')

    def _arping(self, ri, interface_name, ip_address):
        arping_cmd = ['arping', '-A',
                      '-I', interface_name,
                      '-c', self.conf.send_arp_for_ha,
                      ip_address]
        try:
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          namespace=ri.ns_name)
            ip_wrapper.netns.execute(arping_cmd, check_exit_code=True)
        except Exception as e:
            LOG.error(_("Failed sending gratuitous ARP: %s"), str(e))

    def _send_gratuitous_arp_packet(self, ri, interface_name, ip_address):
        if self.conf.send_arp_for_ha > 0:
            eventlet.spawn_n(self._arping, ri, interface_name, ip_address)

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def external_gateway_added(self, ri, ex_gw_port,
                               interface_name, internal_cidrs):

        self.driver.plug(ex_gw_port['network_id'],
                         ex_gw_port['id'], interface_name,
                         ex_gw_port['mac_address'],
                         bridge=self.conf.external_network_bridge,
                         namespace=ri.ns_name,
                         prefix=EXTERNAL_DEV_PREFIX)

        # Compute a list of addresses this router is supposed to have.
        # This avoids unnecessarily removing those addresses and
        # causing a momentarily network outage.
        floating_ips = ri.router.get(l3_constants.FLOATINGIP_KEY, [])
        preserve_ips = [ip['floating_ip_address'] + FLOATING_IP_CIDR_SUFFIX
                        for ip in floating_ips]

        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ri.ns_name,
                            preserve_ips=preserve_ips)
        ip_address = ex_gw_port['ip_cidr'].split('/')[0]
        self._send_gratuitous_arp_packet(ri, interface_name, ip_address)

        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if ex_gw_port['subnet']['gateway_ip']:
            cmd = ['route', 'add', 'default', 'gw', gw_ip]
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          namespace=ri.ns_name)
            ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def external_gateway_removed(self, ri, ex_gw_port,
                                 interface_name, internal_cidrs):

        self.driver.unplug(interface_name,
                           bridge=self.conf.external_network_bridge,
                           namespace=ri.ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)

    def metadata_filter_rules(self):
        rules = []
        if self.conf.enable_metadata_proxy:
            rules.append(('INPUT', '-s 0.0.0.0/0 -d 127.0.0.1 '
                          '-p tcp -m tcp --dport %s '
                          '-j ACCEPT' % self.conf.metadata_port))
        return rules

    def metadata_nat_rules(self):
        rules = []
        if self.conf.enable_metadata_proxy:
            rules.append(('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                          '-p tcp -m tcp --dport 80 -j REDIRECT '
                          '--to-port %s' % self.conf.metadata_port))
        return rules

    def external_gateway_nat_rules(self, ex_gw_ip, internal_cidrs,
                                   interface_name):
        rules = [('POSTROUTING', '! -i %(interface_name)s '
                  '! -o %(interface_name)s -m conntrack ! '
                  '--ctstate DNAT -j ACCEPT' %
                  {'interface_name': interface_name})]
        for cidr in internal_cidrs:
            rules.extend(self.internal_network_nat_rules(ex_gw_ip, cidr))
        return rules

    def internal_network_added(self, ri, network_id, port_id,
                               internal_cidr, mac_address):
        interface_name = self.get_internal_device_name(port_id)
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ri.ns_name):
            self.driver.plug(network_id, port_id, interface_name, mac_address,
                             namespace=ri.ns_name,
                             prefix=INTERNAL_DEV_PREFIX)

        self.driver.init_l3(interface_name, [internal_cidr],
                            namespace=ri.ns_name)
        ip_address = internal_cidr.split('/')[0]
        self._send_gratuitous_arp_packet(ri, interface_name, ip_address)

    def internal_network_removed(self, ri, port_id, internal_cidr):
        interface_name = self.get_internal_device_name(port_id)
        if ip_lib.device_exists(interface_name,
                                root_helper=self.root_helper,
                                namespace=ri.ns_name):
            self.driver.unplug(interface_name, namespace=ri.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def internal_network_nat_rules(self, ex_gw_ip, internal_cidr):
        rules = [('snat', '-s %s -j SNAT --to-source %s' %
                 (internal_cidr, ex_gw_ip))]
        return rules

    def floating_forward_rules(self, floating_ip, fixed_ip):
        return [('PREROUTING', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', '-s %s -j SNAT --to %s' %
                 (fixed_ip, floating_ip))]

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.debug(_('Got router deleted notification for %s'), router_id)
        self.removed_routers.add(router_id)

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug(_('Got routers updated notification :%s'), routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            self.updated_routers.update(routers)

    def router_removed_from_agent(self, context, payload):
        LOG.debug(_('Got router removed from agent :%r'), payload)
        self.removed_routers.add(payload['router_id'])

    def router_added_to_agent(self, context, payload):
        LOG.debug(_('Got router added to agent :%r'), payload)
        self.routers_updated(context, payload)

    def _process_routers(self, routers, all_routers=False):
        pool = eventlet.GreenPool()
        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        target_ex_net_id = self._fetch_external_net_id()
        # if routers are all the routers we have (They are from router sync on
        # starting or when error occurs during running), we seek the
        # routers which should be removed.
        # If routers are from server side notification, we seek them
        # from subset of incoming routers and ones we have now.
        if all_routers:
            prev_router_ids = set(self.router_info)
        else:
            prev_router_ids = set(self.router_info) & set(
                [router['id'] for router in routers])
        cur_router_ids = set()
        for r in routers:
            # If namespaces are disabled, only process the router associated
            # with the configured agent id.
            if (not self.conf.use_namespaces and
                r['id'] != self.conf.router_id):
                continue
            ex_net_id = (r['external_gateway_info'] or {}).get('network_id')
            if not ex_net_id and not self.conf.handle_internal_only_routers:
                continue
            if (target_ex_net_id and ex_net_id and
                ex_net_id != target_ex_net_id):
                # Double check that our single external_net_id has not changed
                # by forcing a check by RPC.
                if (ex_net_id != self._fetch_external_net_id(force=True)):
                    continue
            cur_router_ids.add(r['id'])
            if r['id'] not in self.router_info:
                self._router_added(r['id'], r)
            ri = self.router_info[r['id']]
            ri.router = r
            pool.spawn_n(self.process_router, ri)
        # identify and remove routers that no longer exist
        for router_id in prev_router_ids - cur_router_ids:
            pool.spawn_n(self._router_removed, router_id)
        pool.waitall()

    @lockutils.synchronized('l3-agent', 'neutron-')
    def _rpc_loop(self):
        # _rpc_loop and _sync_routers_task will not be
        # executed in the same time because of lock.
        # so we can clear the value of updated_routers
        # and removed_routers, but they can be updated by
        # updated_routers and removed_routers rpc call
        try:
            LOG.debug(_("Starting RPC loop for %d updated routers"),
                      len(self.updated_routers))
            if self.updated_routers:
                # We're capturing and clearing the list, and will
                # process the "captured" updates in this loop,
                # and any updates that happen due to a context switch
                # will be picked up on the next pass.
                updated_routers = set(self.updated_routers)
                self.updated_routers.clear()
                router_ids = list(updated_routers)
                routers = self.plugin_rpc.get_routers(
                    self.context, router_ids)
                # routers with admin_state_up=false will not be in the fetched
                fetched = set([r['id'] for r in routers])
                self.removed_routers.update(updated_routers - fetched)

                self._process_routers(routers)
            self._process_router_delete()
            LOG.debug(_("RPC loop successfully completed"))
        except Exception:
            LOG.exception(_("Failed synchronizing routers"))
            self.fullsync = True

    def _process_router_delete(self):
        current_removed_routers = list(self.removed_routers)
        for router_id in current_removed_routers:
            self._router_removed(router_id)
            self.removed_routers.remove(router_id)

    def _router_ids(self):
        if not self.conf.use_namespaces:
            return [self.conf.router_id]

    @periodic_task.periodic_task
    @lockutils.synchronized('l3-agent', 'neutron-')
    def _sync_routers_task(self, context):
        if self.services_sync:
            super(L3NATAgent, self).process_services_sync(context)
        LOG.debug(_("Starting _sync_routers_task - fullsync:%s"),
                  self.fullsync)
        if not self.fullsync:
            return
        try:
            router_ids = self._router_ids()
            self.updated_routers.clear()
            self.removed_routers.clear()
            routers = self.plugin_rpc.get_routers(
                context, router_ids)

            LOG.debug(_('Processing :%r'), routers)
            self._process_routers(routers, all_routers=True)
            self.fullsync = False
            LOG.debug(_("_sync_routers_task successfully completed"))
        except rpc_common.RPCException:
            LOG.exception(_("Failed synchronizing routers due to RPC error"))
            self.fullsync = True
            return
        except Exception:
            LOG.exception(_("Failed synchronizing routers"))
            self.fullsync = True

        # Resync is not necessary for the cleanup of stale
        # namespaces.
        if self._delete_stale_namespaces:
            self._cleanup_namespaces(routers)

    def after_start(self):
        LOG.info(_("L3 agent started"))

    def _update_routing_table(self, ri, operation, route):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop']]
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=ri.ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def routes_updated(self, ri):
        new_routes = ri.router['routes']
        old_routes = ri.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug(_("Added route entry is '%s'"), route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            #replace success even if there is no existing route
            self._update_routing_table(ri, 'replace', route)
        for route in removes:
            LOG.debug(_("Removed route entry is '%s'"), route)
            self._update_routing_table(ri, 'delete', route)
        ri.routes = new_routes


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-l3-agent',
            'host': host,
            'topic': topics.L3_AGENT,
            'configurations': {
                'use_namespaces': self.conf.use_namespaces,
                'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'gateway_external_network_id':
                self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver},
            'start_flag': True,
            'agent_type': l3_constants.AGENT_TYPE_L3}
        report_interval = cfg.CONF.AGENT.report_interval
        self.use_call = True
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug(_("Report state task started"))
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = self._get_ex_gw_port(ri)
            if ex_gw_port:
                num_ex_gw_ports += 1
            num_interfaces += len(ri.router.get(l3_constants.INTERFACE_KEY,
                                                []))
            num_floating_ips += len(ri.router.get(l3_constants.FLOATINGIP_KEY,
                                                  []))
        configurations = self.agent_state['configurations']
        configurations['routers'] = num_routers
        configurations['ex_gw_ports'] = num_ex_gw_ports
        configurations['interfaces'] = num_interfaces
        configurations['floating_ips'] = num_floating_ips
        try:
            self.state_rpc.report_state(self.context, self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
            LOG.debug(_("Report state task successfully completed"))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_("Neutron server does not support state report."
                       " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def main(manager='neutron.agent.l3_agent.L3NATAgentWithStateReport'):
    eventlet.monkey_patch()
    conf = cfg.CONF
    conf.register_opts(L3NATAgent.OPTS)
    config.register_interface_driver_opts_helper(conf)
    config.register_use_namespaces_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    config.register_root_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    conf(project='neutron')
    config.setup_logging(conf)
    legacy.modernize_quantum_config(conf)
    server = neutron_service.Service.create(
        binary='neutron-l3-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    service.launch(server).wait()
