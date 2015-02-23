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
from oslo_config import cfg
import oslo_messaging
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import timeutils

from neutron.agent.l3 import dvr
from neutron.agent.l3 import dvr_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import event_observers
from neutron.agent.l3 import ha
from neutron.agent.l3 import ha_router
from neutron.agent.l3 import legacy_router
from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_processing_queue as queue
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ra
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent import rpc as agent_rpc
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as common_utils
from neutron import context as n_context
from neutron.i18n import _LE, _LI, _LW
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import periodic_task
from neutron.services import advanced_service as adv_svc
try:
    from neutron_fwaas.services.firewall.agents.l3reference \
        import firewall_l3_agent
except Exception:
    # TODO(dougw) - REMOVE THIS FROM NEUTRON; during l3_agent refactor only
    from neutron.services.firewall.agents.l3reference import firewall_l3_agent

LOG = logging.getLogger(__name__)
# TODO(Carl) Following constants retained to increase SNR during refactoring
NS_PREFIX = namespaces.NS_PREFIX
INTERNAL_DEV_PREFIX = namespaces.INTERNAL_DEV_PREFIX
EXTERNAL_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX


class L3PluginApi(object):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.
        1.1 - Floating IP operational status updates
        1.2 - DVR support: new L3 plugin methods added.
              - get_ports_by_subnet
              - get_agent_gateway_port
              Needed by the agent when operating in DVR/DVR_SNAT mode
        1.3 - Get the list of activated services

    """

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'sync_routers', host=self.host,
                          router_ids=router_ids)

    def get_external_network_id(self, context):
        """Make a remote process call to retrieve the external network id.

        @raise oslo_messaging.RemoteError: with TooManyExternalNetworks as
                                           exc_type if there are more than one
                                           external network
        """
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_external_network_id', host=self.host)

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Call the plugin update floating IPs's operational status."""
        cctxt = self.client.prepare(version='1.1')
        return cctxt.call(context, 'update_floatingip_statuses',
                          router_id=router_id, fip_statuses=fip_statuses)

    def get_ports_by_subnet(self, context, subnet_id):
        """Retrieve ports by subnet id."""
        cctxt = self.client.prepare(version='1.2')
        return cctxt.call(context, 'get_ports_by_subnet', host=self.host,
                          subnet_id=subnet_id)

    def get_agent_gateway_port(self, context, fip_net):
        """Get or create an agent_gateway_port."""
        cctxt = self.client.prepare(version='1.2')
        return cctxt.call(context, 'get_agent_gateway_port',
                          network_id=fip_net, host=self.host)

    def get_service_plugin_list(self, context):
        """Make a call to get the list of activated services."""
        cctxt = self.client.prepare(version='1.3')
        return cctxt.call(context, 'get_service_plugin_list')


class L3NATAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback,
                 ha.AgentMixin,
                 dvr.AgentMixin,
                 manager.Manager):
    """Manager for L3NatAgent

        API version history:
        1.0 initial Version
        1.1 changed the type of the routers parameter
            to the routers_updated method.
            It was previously a list of routers in dict format.
            It is now a list of router IDs only.
            Per rpc versioning rules,  it is backwards compatible.
        1.2 - DVR support: new L3 agent methods added.
              - add_arp_entry
              - del_arp_entry
              Needed by the L3 service when dealing with DVR
    """
    target = oslo_messaging.Target(version='1.2')

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.router_info = {}

        self._check_config_params()

        self.process_monitor = external_process.ProcessMonitor(
            config=self.conf,
            resource_type='router')

        try:
            self.driver = importutils.import_object(
                self.conf.interface_driver,
                self.conf
            )
        except Exception:
            LOG.error(_LE("Error importing interface driver "
                          "'%s'"), self.conf.interface_driver)
            raise SystemExit(1)

        self.context = n_context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, host)
        self.fullsync = True

        # Get the list of service plugins from Neutron Server
        # This is the first place where we contact neutron-server on startup
        # so retry in case its not ready to respond.
        retry_count = 5
        while True:
            retry_count = retry_count - 1
            try:
                self.neutron_service_plugins = (
                    self.plugin_rpc.get_service_plugin_list(self.context))
            except oslo_messaging.RemoteError as e:
                with excutils.save_and_reraise_exception() as ctx:
                    ctx.reraise = False
                    LOG.warning(_LW('l3-agent cannot check service plugins '
                                    'enabled at the neutron server when '
                                    'startup due to RPC error. It happens '
                                    'when the server does not support this '
                                    'RPC API. If the error is '
                                    'UnsupportedVersion you can ignore this '
                                    'warning. Detail message: %s'), e)
                self.neutron_service_plugins = None
            except oslo_messaging.MessagingTimeout as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if retry_count > 0:
                        ctx.reraise = False
                        LOG.warning(_LW('l3-agent cannot check service '
                                        'plugins enabled on the neutron '
                                        'server. Retrying. '
                                        'Detail message: %s'), e)
                        continue
            break

        self.namespaces_manager = namespace_manager.NamespaceManager(
            self.conf,
            self.driver,
            self.conf.use_namespaces)

        self._queue = queue.RouterProcessingQueue()
        self.event_observers = event_observers.L3EventObservers()
        super(L3NATAgent, self).__init__(conf=self.conf)

        self.target_ex_net_id = None
        self.use_ipv6 = ipv6_utils.is_enabled()

        if self.conf.enable_metadata_proxy:
            self.metadata_driver = metadata_driver.MetadataDriver(self)
            self.event_observers.add(self.metadata_driver)

    def _check_config_params(self):
        """Check items in configuration files.

        Check for required and invalid configuration items.
        The actual values are not verified for correctness.
        """
        if not self.conf.interface_driver:
            msg = _LE('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(1)

        if not self.conf.use_namespaces and not self.conf.router_id:
            msg = _LE('Router id is required if not using namespaces.')
            LOG.error(msg)
            raise SystemExit(1)

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
        except oslo_messaging.RemoteError as e:
            with excutils.save_and_reraise_exception() as ctx:
                if e.exc_type == 'TooManyExternalNetworks':
                    ctx.reraise = False
                    msg = _(
                        "The 'gateway_external_network_id' option must be "
                        "configured for this agent as Neutron has more than "
                        "one external network.")
                    raise Exception(msg)

    def _create_router(self, router_id, router):
        # TODO(Carl) We need to support a router that is both HA and DVR.  The
        # patch that enables it will replace these lines.  See bug #1365473.
        if router.get('distributed') and router.get('ha'):
            raise n_exc.DvrHaRouterNotSupported(router_id=router_id)

        args = []
        kwargs = {
            'router_id': router_id,
            'router': router,
            'use_ipv6': self.use_ipv6,
            'agent_conf': self.conf,
            'interface_driver': self.driver,
        }

        if router.get('distributed'):
            kwargs['agent'] = self
            kwargs['host'] = self.host
            return dvr_router.DvrRouter(*args, **kwargs)

        if router.get('ha'):
            return ha_router.HaRouter(*args, **kwargs)

        return legacy_router.LegacyRouter(*args, **kwargs)

    def _router_added(self, router_id, router):
        ri = self._create_router(router_id, router)
        ri.radvd = ra.DaemonMonitor(router['id'],
                                    ri.ns_name,
                                    self.process_monitor,
                                    ri.get_internal_device_name)
        self.event_observers.notify(
            adv_svc.AdvancedService.before_router_added, ri)

        self.router_info[router_id] = ri
        ri.create()
        self.process_router_add(ri)

        if ri.is_ha:
            self.process_ha_router_added(ri)

    def _router_removed(self, router_id):
        ri = self.router_info.get(router_id)
        if ri is None:
            LOG.warn(_LW("Info for router %s were not found. "
                         "Skipping router removal"), router_id)
            return

        self.event_observers.notify(
            adv_svc.AdvancedService.before_router_removed, ri)

        if ri.is_ha:
            self.process_ha_router_removed(ri)

        ri.router['gw_port'] = None
        ri.router[l3_constants.INTERFACE_KEY] = []
        ri.router[l3_constants.FLOATINGIP_KEY] = []
        self.process_router(ri)
        del self.router_info[router_id]
        ri.delete()
        self.event_observers.notify(
            adv_svc.AdvancedService.after_router_removed, ri)

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_LE("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def _get_existing_devices(self, ri):
        ip_wrapper = ip_lib.IPWrapper(namespace=ri.ns_name)
        ip_devs = ip_wrapper.get_devices(exclude_loopback=True)
        return [ip_dev.name for ip_dev in ip_devs]

    def _process_internal_ports(self, ri):
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        existing_port_ids = set([p['id'] for p in ri.internal_ports])
        current_port_ids = set([p['id'] for p in internal_ports
                                if p['admin_state_up']])
        new_ports = [p for p in internal_ports if
                     p['id'] in current_port_ids and
                     p['id'] not in existing_port_ids]
        old_ports = [p for p in ri.internal_ports if
                     p['id'] not in current_port_ids]

        new_ipv6_port = False
        old_ipv6_port = False
        for p in new_ports:
            self._set_subnet_info(p)
            self.internal_network_added(ri, p)
            ri.internal_ports.append(p)
            if ri.router['distributed']:
                ri._set_subnet_arp_info(p)
            if (not new_ipv6_port and
                    netaddr.IPNetwork(p['subnet']['cidr']).version == 6):
                new_ipv6_port = True

        for p in old_ports:
            self.internal_network_removed(ri, p)
            ri.internal_ports.remove(p)
            if (not old_ipv6_port and
                    netaddr.IPNetwork(p['subnet']['cidr']).version == 6):
                old_ipv6_port = True

        # Enable RA
        if new_ipv6_port or old_ipv6_port:
            ri.radvd.enable(internal_ports)

        existing_devices = self._get_existing_devices(ri)
        current_internal_devs = set([n for n in existing_devices
                                     if n.startswith(INTERNAL_DEV_PREFIX)])
        current_port_devs = set([ri.get_internal_device_name(id) for
                                 id in current_port_ids])
        stale_devs = current_internal_devs - current_port_devs
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale internal router device: %s',
                      stale_dev)
            self.driver.unplug(stale_dev,
                               namespace=ri.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def _process_external_gateway(self, ri):
        ex_gw_port = ri.get_ex_gw_port()
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                         ri.ex_gw_port and ri.ex_gw_port['id'])

        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port:
            def _gateway_ports_equal(port1, port2):
                def _get_filtered_dict(d, ignore):
                    return dict((k, v) for k, v in d.iteritems()
                                if k not in ignore)

                keys_to_ignore = set(['binding:host_id'])
                port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
                port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
                return port1_filtered == port2_filtered

            self._set_subnet_info(ex_gw_port)
            if not ri.ex_gw_port:
                self.external_gateway_added(ri, ex_gw_port, interface_name)
            elif not _gateway_ports_equal(ex_gw_port, ri.ex_gw_port):
                self.external_gateway_updated(ri, ex_gw_port, interface_name)
        elif not ex_gw_port and ri.ex_gw_port:
            self.external_gateway_removed(ri, ri.ex_gw_port, interface_name)

        existing_devices = self._get_existing_devices(ri)
        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX)
                      and dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale external router device: %s',
                      stale_dev)
            self.driver.unplug(stale_dev,
                               bridge=self.conf.external_network_bridge,
                               namespace=ri.ns_name,
                               prefix=EXTERNAL_DEV_PREFIX)

        # Process SNAT rules for external gateway
        if (not ri.router['distributed'] or
            ex_gw_port and self.get_gw_port_host(ri.router) == self.host):
            ri.perform_snat_action(self._handle_router_snat_rules,
                                   interface_name)

    def _update_fip_statuses(self, ri, existing_floating_ips, fip_statuses):
        # Identify floating IPs which were disabled
        ri.floating_ips = set(fip_statuses.keys())
        for fip_id in existing_floating_ips - ri.floating_ips:
            fip_statuses[fip_id] = l3_constants.FLOATINGIP_STATUS_DOWN
        # Update floating IP status on the neutron server
        self.plugin_rpc.update_floatingip_statuses(
            self.context, ri.router_id, fip_statuses)

    def _process_ha_router(self, ri):
        if ri.is_ha:
            if ri.ha_port:
                ri.spawn_keepalived()
            else:
                ri.disable_keepalived()

    def _process_external(self, ri):
        try:
            with ri.iptables_manager.defer_apply():
                self._process_external_gateway(ri)
                ex_gw_port = ri.get_ex_gw_port()
                # TODO(Carl) Return after setting existing_floating_ips and
                # still call _update_fip_statuses?
                if not ex_gw_port:
                    return

                # Process SNAT/DNAT rules and addresses for floating IPs
                existing_floating_ips = ri.floating_ips
                if ri.router['distributed']:
                    self.create_dvr_fip_interfaces(ri, ex_gw_port)
                ri.process_snat_dnat_for_fip()

            # Once NAT rules for floating IPs are safely in place
            # configure their addresses on the external gateway port
            interface_name = self._get_external_device_interface_name(
                ri, ex_gw_port)
            fip_statuses = ri.configure_fip_addresses(interface_name)

        except (n_exc.FloatingIpSetupException,
                n_exc.IpTablesApplyException) as e:
                # All floating IPs must be put in error state
                LOG.exception(e)
                fip_statuses = ri.put_fips_in_error_state()

        self._update_fip_statuses(ri, existing_floating_ips, fip_statuses)

    @common_utils.exception_logger()
    def process_router(self, ri):
        # TODO(mrsmith) - we shouldn't need to check here
        if 'distributed' not in ri.router:
            ri.router['distributed'] = False
        ex_gw_port = ri.get_ex_gw_port()
        if ri.router.get('distributed') and ex_gw_port:
            ri.fip_ns = self.get_fip_ns(ex_gw_port['network_id'])
            ri.fip_ns.scan_fip_ports(ri)
        self._process_internal_ports(ri)
        self._process_external(ri)
        # Process static routes for router
        ri.routes_updated()

        # Enable or disable keepalived for ha routers
        self._process_ha_router(ri)

        # Update ex_gw_port and enable_snat on the router info cache
        ri.ex_gw_port = ex_gw_port
        ri.snat_ports = ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])
        ri.enable_snat = ri.router.get('enable_snat')

    def _handle_router_snat_rules(self, ri, ex_gw_port,
                                  interface_name, action):
        # Remove all the rules
        # This is safe because if use_namespaces is set as False
        # then the agent can only configure one router, otherwise
        # each router's SNAT rules will be in their own namespace
        if not ri.router['distributed']:
            iptables_manager = ri.iptables_manager
        elif ri.snat_iptables_manager:
            iptables_manager = ri.snat_iptables_manager
        else:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        iptables_manager.ipv4['nat'].empty_chain('snat')

        if not ri.router['distributed']:
            # Add back the jump to float-snat
            iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        # And add them back if the action is add_rules
        if action == 'add_rules' and ex_gw_port:
            # ex_gw_port should not be None in this case
            # NAT rules are added only if ex_gw_port has an IPv4 address
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                if netaddr.IPAddress(ex_gw_ip).version == 4:
                    rules = self.external_gateway_nat_rules(ex_gw_ip,
                                                            interface_name)
                    for rule in rules:
                        iptables_manager.ipv4['nat'].add_rule(*rule)
                    break
        iptables_manager.apply()

    def create_dvr_fip_interfaces(self, ri, ex_gw_port):
        floating_ips = ri.get_floating_ips()
        fip_agent_port = self.get_floating_agent_gw_interface(
            ri, ex_gw_port['network_id'])
        LOG.debug("FloatingIP agent gateway port received from the plugin: "
                  "%s", fip_agent_port)
        if floating_ips:
            is_first = ri.fip_ns.subscribe(ri.router_id)
            if is_first and fip_agent_port:
                if 'subnet' not in fip_agent_port:
                    LOG.error(_LE('Missing subnet/agent_gateway_port'))
                else:
                    self._set_subnet_info(fip_agent_port)
                    ri.fip_ns.create_gateway_port(fip_agent_port)

        if ri.fip_ns.agent_gateway_port and floating_ips:
            if ri.dist_fip_count == 0:
                ri.fip_ns.create_rtr_2_fip_link(ri)

                # kicks the FW Agent to add rules for the IR namespace if
                # configured
                self.process_router_add(ri)

    def _get_external_device_interface_name(self, ri, ex_gw_port):
        if ri.router['distributed']:
            fip_int = ri.fip_ns.get_int_device_name(ri.router_id)
            if ip_lib.device_exists(fip_int, namespace=ri.fip_ns.get_name()):
                return ri.fip_ns.get_rtr_ext_device_name(ri.router_id)
        else:
            return self.get_external_device_name(ex_gw_port['id'])

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_floating_agent_gw_interface(self, ri, ext_net_id):
        """Filter Floating Agent GW port for the external network."""
        fip_ports = ri.router.get(l3_constants.FLOATINGIP_AGENT_INTF_KEY, [])
        return next(
            (p for p in fip_ports if p['network_id'] == ext_net_id), None)

    def external_gateway_added(self, ri, ex_gw_port, interface_name):
        if ri.router['distributed']:
            ip_wrapr = ip_lib.IPWrapper(namespace=ri.ns_name)
            ip_wrapr.netns.execute(['sysctl', '-w',
                                   'net.ipv4.conf.all.send_redirects=0'])
            snat_ports = self.get_snat_interfaces(ri)
            for p in ri.internal_ports:
                gateway = self._map_internal_interfaces(ri, p, snat_ports)
                id_name = ri.get_internal_device_name(p['id'])
                if gateway:
                    self._snat_redirect_add(ri, gateway['fixed_ips'][0]
                                            ['ip_address'], p, id_name)

            if (self.conf.agent_mode == l3_constants.L3_AGENT_MODE_DVR_SNAT and
                self.get_gw_port_host(ri.router) == self.host):
                self._create_dvr_gateway(ri, ex_gw_port, interface_name,
                                         snat_ports)
            for port in snat_ports:
                for ip in port['fixed_ips']:
                    ri._update_arp_entry(ip['ip_address'],
                                         port['mac_address'],
                                         ip['subnet_id'],
                                         'add')
            return

        # Compute a list of addresses this router is supposed to have.
        # This avoids unnecessarily removing those addresses and
        # causing a momentarily network outage.
        floating_ips = ri.get_floating_ips()
        preserve_ips = [common_utils.ip_to_cidr(ip['floating_ip_address'])
                        for ip in floating_ips]

        self._external_gateway_added(ri, ex_gw_port, interface_name,
                                     ri.ns_name, preserve_ips)

        if ri.is_ha:
            ri._ha_external_gateway_added(ex_gw_port, interface_name)
            ri._ha_disable_addressing_on_interface(interface_name)

    def external_gateway_updated(self, ri, ex_gw_port, interface_name):
        preserve_ips = []
        if ri.router['distributed']:
            if (self.conf.agent_mode == l3_constants.L3_AGENT_MODE_DVR_SNAT and
                self.get_gw_port_host(ri.router) == self.host):
                ns_name = ri.snat_namespace.name
            else:
                # no centralized SNAT gateway for this node/agent
                LOG.debug("not hosting snat for router: %s", ri.router['id'])
                return
        else:
            ns_name = ri.ns_name
            floating_ips = ri.get_floating_ips()
            preserve_ips = [common_utils.ip_to_cidr(ip['floating_ip_address'])
                            for ip in floating_ips]

        self._external_gateway_added(ri, ex_gw_port, interface_name,
                                     ns_name, preserve_ips)

        if ri.is_ha:
            ri._ha_external_gateway_updated(ex_gw_port, interface_name)

    def _external_gateway_added(self, ri, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        if not ip_lib.device_exists(interface_name, namespace=ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ns_name,
                             prefix=EXTERNAL_DEV_PREFIX)

        if not ri.is_ha:
            self.driver.init_l3(
                interface_name, [ex_gw_port['ip_cidr']], namespace=ns_name,
                gateway=ex_gw_port['subnet'].get('gateway_ip'),
                extra_subnets=ex_gw_port.get('extra_subnets', []),
                preserve_ips=preserve_ips)
            ip_address = ex_gw_port['ip_cidr'].split('/')[0]
            ip_lib.send_gratuitous_arp(ns_name,
                                       interface_name,
                                       ip_address,
                                       self.conf.send_arp_for_ha)

    def external_gateway_removed(self, ri, ex_gw_port, interface_name):
        if ri.router['distributed']:
            # TODO(Carl) Should this be calling process_snat_dnat_for_fip?
            ri.process_floating_ip_nat_rules()
            if ri.fip_ns:
                to_fip_interface_name = (
                    self._get_external_device_interface_name(ri, ex_gw_port))
                ri.process_floating_ip_addresses(to_fip_interface_name)
            for p in ri.internal_ports:
                internal_interface = ri.get_internal_device_name(p['id'])
                self._snat_redirect_remove(ri, p, internal_interface)

            if (self.conf.agent_mode == l3_constants.L3_AGENT_MODE_DVR_SNAT
                and self.get_gw_port_host(ri.router) == self.host):
                ns_name = ri.snat_namespace.name
            else:
                # not hosting agent - no work to do
                LOG.debug('DVR: CSNAT not hosted: %s', ex_gw_port)
                return
        else:
            ns_name = ri.ns_name

        if ri.is_ha:
            ri._ha_external_gateway_removed(interface_name)

        self.driver.unplug(interface_name,
                           bridge=self.conf.external_network_bridge,
                           namespace=ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)
        if ri.router['distributed']:
            ri.delete_snat_namespace()

    def external_gateway_nat_rules(self, ex_gw_ip, interface_name):
        rules = [('POSTROUTING', '! -i %(interface_name)s '
                  '! -o %(interface_name)s -m conntrack ! '
                  '--ctstate DNAT -j ACCEPT' %
                  {'interface_name': interface_name}),
                 ('snat', '-o %s -j SNAT --to-source %s' %
                  (interface_name, ex_gw_ip))]
        return rules

    def _internal_network_added(self, ns_name, network_id, port_id,
                                internal_cidr, mac_address,
                                interface_name, prefix, is_ha=False):
        if not ip_lib.device_exists(interface_name, namespace=ns_name):
            self.driver.plug(network_id, port_id, interface_name, mac_address,
                             namespace=ns_name,
                             prefix=prefix)

        if not is_ha:
            self.driver.init_l3(interface_name, [internal_cidr],
                                namespace=ns_name)
            ip_address = internal_cidr.split('/')[0]
            ip_lib.send_gratuitous_arp(ns_name,
                                       interface_name,
                                       ip_address,
                                       self.conf.send_arp_for_ha)

    def internal_network_added(self, ri, port):
        network_id = port['network_id']
        port_id = port['id']
        internal_cidr = port['ip_cidr']
        mac_address = port['mac_address']

        interface_name = ri.get_internal_device_name(port_id)

        self._internal_network_added(ri.ns_name, network_id, port_id,
                                     internal_cidr, mac_address,
                                     interface_name, INTERNAL_DEV_PREFIX,
                                     ri.is_ha)

        if ri.is_ha:
            ri._ha_disable_addressing_on_interface(interface_name)
            ri._add_vip(internal_cidr, interface_name)

        ex_gw_port = ri.get_ex_gw_port()
        if ri.router['distributed'] and ex_gw_port:
            snat_ports = self.get_snat_interfaces(ri)
            sn_port = self._map_internal_interfaces(ri, port, snat_ports)
            if sn_port:
                self._snat_redirect_add(ri, sn_port['fixed_ips'][0]
                                        ['ip_address'], port, interface_name)
                if (self.conf.agent_mode == l3_constants.L3_AGENT_MODE_DVR_SNAT
                    and self.get_gw_port_host(ri.router) == self.host):
                    ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
                        ri.router['id'])
                    self._set_subnet_info(sn_port)
                    interface_name = (
                          self.get_snat_int_device_name(sn_port['id']))
                    self._internal_network_added(ns_name,
                                                 sn_port['network_id'],
                                                 sn_port['id'],
                                                 sn_port['ip_cidr'],
                                                 sn_port['mac_address'],
                                                 interface_name,
                                                 dvr.SNAT_INT_DEV_PREFIX)

    def internal_network_removed(self, ri, port):
        port_id = port['id']
        interface_name = ri.get_internal_device_name(port_id)
        if ri.router['distributed'] and ri.ex_gw_port:
            # DVR handling code for SNAT
            self._snat_redirect_remove(ri, port, interface_name)
            if (self.conf.agent_mode == l3_constants.L3_AGENT_MODE_DVR_SNAT
                and ri.ex_gw_port['binding:host_id'] == self.host):
                snat_port = self._map_internal_interfaces(ri, port,
                                                          ri.snat_ports)
                if snat_port:
                    snat_interface = (
                        self.get_snat_int_device_name(snat_port['id'])
                    )
                    ns_name = ri.snat_namespace.name
                    prefix = dvr.SNAT_INT_DEV_PREFIX
                    if ip_lib.device_exists(snat_interface,
                                            namespace=ns_name):
                        self.driver.unplug(snat_interface, namespace=ns_name,
                                           prefix=prefix)

        if ip_lib.device_exists(interface_name, namespace=ri.ns_name):
            if ri.is_ha:
                ri._clear_vips(interface_name)
            self.driver.unplug(interface_name, namespace=ri.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.debug('Got router deleted notification for %s', router_id)
        update = queue.RouterUpdate(router_id,
                                    queue.PRIORITY_RPC,
                                    action=queue.DELETE_ROUTER)
        self._queue.add(update)

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.debug('Got routers updated notification :%s', routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            for id in routers:
                update = queue.RouterUpdate(id, queue.PRIORITY_RPC)
                self._queue.add(update)

    def router_removed_from_agent(self, context, payload):
        LOG.debug('Got router removed from agent :%r', payload)
        router_id = payload['router_id']
        update = queue.RouterUpdate(router_id,
                                    queue.PRIORITY_RPC,
                                    action=queue.DELETE_ROUTER)
        self._queue.add(update)

    def router_added_to_agent(self, context, payload):
        LOG.debug('Got router added to agent :%r', payload)
        self.routers_updated(context, payload)

    def _process_router_if_compatible(self, router):
        if (self.conf.external_network_bridge and
            not ip_lib.device_exists(self.conf.external_network_bridge)):
            LOG.error(_LE("The external network bridge '%s' does not exist"),
                      self.conf.external_network_bridge)
            return

        # If namespaces are disabled, only process the router associated
        # with the configured agent id.
        if (not self.conf.use_namespaces and
            router['id'] != self.conf.router_id):
            raise n_exc.RouterNotCompatibleWithAgent(router_id=router['id'])

        # Either ex_net_id or handle_internal_only_routers must be set
        ex_net_id = (router['external_gateway_info'] or {}).get('network_id')
        if not ex_net_id and not self.conf.handle_internal_only_routers:
            raise n_exc.RouterNotCompatibleWithAgent(router_id=router['id'])

        # If target_ex_net_id and ex_net_id are set they must be equal
        target_ex_net_id = self._fetch_external_net_id()
        if (target_ex_net_id and ex_net_id and ex_net_id != target_ex_net_id):
            # Double check that our single external_net_id has not changed
            # by forcing a check by RPC.
            if ex_net_id != self._fetch_external_net_id(force=True):
                raise n_exc.RouterNotCompatibleWithAgent(
                    router_id=router['id'])

        if router['id'] not in self.router_info:
            self._process_added_router(router)
        else:
            self._process_updated_router(router)

    def _process_added_router(self, router):
        # TODO(pcm): Next refactoring will rework this logic
        self._router_added(router['id'], router)
        ri = self.router_info[router['id']]
        ri.router = router
        self.process_router(ri)
        self.event_observers.notify(
            adv_svc.AdvancedService.after_router_added, ri)

    def _process_updated_router(self, router):
        # TODO(pcm): Next refactoring will rework this logic
        ri = self.router_info[router['id']]
        ri.router = router
        self.event_observers.notify(
            adv_svc.AdvancedService.before_router_updated, ri)
        self.process_router(ri)
        self.event_observers.notify(
            adv_svc.AdvancedService.after_router_updated, ri)

    def _process_router_update(self):
        for rp, update in self._queue.each_update_to_next_router():
            LOG.debug("Starting router update for %s", update.id)
            router = update.router
            if update.action != queue.DELETE_ROUTER and not router:
                try:
                    update.timestamp = timeutils.utcnow()
                    routers = self.plugin_rpc.get_routers(self.context,
                                                          [update.id])
                except Exception:
                    msg = _LE("Failed to fetch router information for '%s'")
                    LOG.exception(msg, update.id)
                    self.fullsync = True
                    continue

                if routers:
                    router = routers[0]

            if not router:
                try:
                    self._router_removed(update.id)
                except Exception:
                    # TODO(Carl) Stop this fullsync non-sense.  Just retry this
                    # one router by sticking the update at the end of the queue
                    # at a lower priority.
                    self.fullsync = True
                continue

            try:
                self._process_router_if_compatible(router)
            except n_exc.RouterNotCompatibleWithAgent as e:
                LOG.exception(e.msg)
                # Was the router previously handled by this agent?
                if router['id'] in self.router_info:
                    LOG.error(_LE("Removing incompatible router '%s'"),
                              router['id'])
                    self._router_removed(router['id'])
            except Exception:
                msg = _LE("Failed to process compatible router '%s'")
                LOG.exception(msg, update.id)
                self.fullsync = True
                continue

            LOG.debug("Finished a router update for %s", update.id)
            rp.fetched_and_processed(update.timestamp)

    def _process_routers_loop(self):
        LOG.debug("Starting _process_routers_loop")
        pool = eventlet.GreenPool(size=8)
        while True:
            pool.spawn_n(self._process_router_update)

    @periodic_task.periodic_task
    def periodic_sync_routers_task(self, context):
        self.process_services_sync(context)
        LOG.debug("Starting periodic_sync_routers_task - fullsync:%s",
                  self.fullsync)
        if not self.fullsync:
            return

        # self.fullsync is True at this point. If an exception -- caught or
        # uncaught -- prevents setting it to False below then the next call
        # to periodic_sync_routers_task will re-enter this code and try again.

        # Context manager self.namespaces_manager captures a picture of
        # namespaces *before* fetch_and_sync_all_routers fetches the full list
        # of routers from the database.  This is important to correctly
        # identify stale ones.

        try:
            with self.namespaces_manager as ns_manager:
                self.fetch_and_sync_all_routers(context, ns_manager)
        except n_exc.AbortSyncRouters:
            self.fullsync = True

    def fetch_and_sync_all_routers(self, context, ns_manager):
        prev_router_ids = set(self.router_info)
        timestamp = timeutils.utcnow()

        try:
            if self.conf.use_namespaces:
                routers = self.plugin_rpc.get_routers(context)
            else:
                routers = self.plugin_rpc.get_routers(context,
                                                      [self.conf.router_id])

        except oslo_messaging.MessagingException:
            LOG.exception(_LE("Failed synchronizing routers due to RPC error"))
            raise n_exc.AbortSyncRouters()
        else:
            LOG.debug('Processing :%r', routers)
            for r in routers:
                ns_manager.keep_router(r['id'])
                update = queue.RouterUpdate(r['id'],
                                            queue.PRIORITY_SYNC_ROUTERS_TASK,
                                            router=r,
                                            timestamp=timestamp)
                self._queue.add(update)
            self.fullsync = False
            LOG.debug("periodic_sync_routers_task successfully completed")

            curr_router_ids = set([r['id'] for r in routers])

            # Delete routers that have disappeared since the last sync
            for router_id in prev_router_ids - curr_router_ids:
                ns_manager.keep_router(router_id)
                update = queue.RouterUpdate(router_id,
                                            queue.PRIORITY_SYNC_ROUTERS_TASK,
                                            timestamp=timestamp,
                                            action=queue.DELETE_ROUTER)
                self._queue.add(update)

    def after_start(self):
        eventlet.spawn_n(self._process_routers_loop)
        LOG.info(_LI("L3 agent started"))
        # When L3 agent is ready, we immediately do a full sync
        self.periodic_sync_routers_task(self.context)


class L3NATAgentWithStateReport(L3NATAgent):

    def __init__(self, host, conf=None):
        super(L3NATAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron-l3-agent',
            'host': host,
            'topic': topics.L3_AGENT,
            'configurations': {
                'agent_mode': self.conf.agent_mode,
                'use_namespaces': self.conf.use_namespaces,
                'router_id': self.conf.router_id,
                'handle_internal_only_routers':
                self.conf.handle_internal_only_routers,
                'external_network_bridge': self.conf.external_network_bridge,
                'gateway_external_network_id':
                self.conf.gateway_external_network_id,
                'interface_driver': self.conf.interface_driver},
            'start_flag': True,
            'agent_type': l3_constants.AGENT_TYPE_L3}
        report_interval = self.conf.AGENT.report_interval
        self.use_call = True
        if report_interval:
            self.heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self.heartbeat.start(interval=report_interval)

    def _report_state(self):
        LOG.debug("Report state task started")
        num_ex_gw_ports = 0
        num_interfaces = 0
        num_floating_ips = 0
        router_infos = self.router_info.values()
        num_routers = len(router_infos)
        for ri in router_infos:
            ex_gw_port = ri.get_ex_gw_port()
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
            LOG.debug("Report state task successfully completed")
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn(_LW("Neutron server does not support state report."
                         " State report for this agent will be disabled."))
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_LI("agent_updated by server side %s!"), payload)
