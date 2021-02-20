# Copyright (c) 2015 OpenStack Foundation
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

from neutron_lib import constants as lib_constants
from oslo_log import log as logging

from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import utils as common_utils

LOG = logging.getLogger(__name__)


class DvrEdgeRouter(dvr_local_router.DvrLocalRouter):

    def __init__(self, host, *args, **kwargs):
        super(DvrEdgeRouter, self).__init__(host, *args, **kwargs)
        self.snat_namespace = dvr_snat_ns.SnatNamespace(
            self.router_id, self.agent_conf, self.driver, self.use_ipv6)
        self.snat_iptables_manager = None

    def get_gw_ns_name(self):
        return self.snat_namespace.name

    def external_gateway_added(self, ex_gw_port, interface_name):
        super(DvrEdgeRouter, self).external_gateway_added(
            ex_gw_port, interface_name)
        if self._is_this_snat_host():
            self._create_dvr_gateway(ex_gw_port, interface_name)
            # NOTE: When a router is created without a gateway the routes get
            # added to the router namespace, but if we wanted to populate
            # the same routes to the snat namespace after the gateway port
            # is added, we need to call routes_updated here.
            self.routes_updated([], self.router['routes'])
        elif self.snat_namespace.exists():
            # This is the case where the snat was moved manually or
            # rescheduled to a different agent when the agent was dead.
            LOG.debug("SNAT was moved or rescheduled to a different host "
                      "and does not match with the current host. This is "
                      "a stale namespace %s and will be cleared from the "
                      "current dvr_snat host.", self.snat_namespace.name)
            self.external_gateway_removed(ex_gw_port, interface_name)

    def _list_centralized_floating_ip_cidrs(self):
        # Compute a list of addresses this gw is supposed to have.
        # This avoids unnecessarily removing those addresses and
        # causing a momentarily network outage.
        floating_ips = self.get_floating_ips()
        return [common_utils.ip_to_cidr(ip['floating_ip_address'])
                for ip in floating_ips
                if ip.get(lib_constants.DVR_SNAT_BOUND)]

    def external_gateway_updated(self, ex_gw_port, interface_name):
        if not self._is_this_snat_host():
            # no centralized SNAT gateway for this node/agent
            LOG.debug("not hosting snat for router: %s", self.router['id'])
            if self.snat_namespace.exists():
                LOG.debug("SNAT was rescheduled to host %s. Clearing snat "
                          "namespace.", self.router.get('gw_port_host'))
                self.driver.unplug(interface_name,
                                   namespace=self.snat_namespace.name,
                                   prefix=router.EXTERNAL_DEV_PREFIX)
                self.snat_namespace.delete()
            return

        if not self.snat_namespace.exists():
            # SNAT might be rescheduled to this agent; need to process like
            # newly created gateway
            return self.external_gateway_added(ex_gw_port, interface_name)
        else:
            preserve_ips = self._list_centralized_floating_ip_cidrs()
            self._external_gateway_added(ex_gw_port,
                                         interface_name,
                                         self.snat_namespace.name,
                                         preserve_ips)

    def _external_gateway_removed(self, ex_gw_port, interface_name):
        super(DvrEdgeRouter, self).external_gateway_removed(ex_gw_port,
                                                            interface_name)
        if not self._is_this_snat_host() and not self.snat_namespace.exists():
            # no centralized SNAT gateway for this node/agent
            LOG.debug("not hosting snat for router: %s", self.router['id'])
            return

        self.driver.unplug(interface_name,
                           namespace=self.snat_namespace.name,
                           prefix=router.EXTERNAL_DEV_PREFIX)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        self._external_gateway_removed(ex_gw_port, interface_name)
        if self.snat_namespace.exists():
            self.snat_namespace.delete()

    def internal_network_added(self, port):
        super(DvrEdgeRouter, self).internal_network_added(port)

        # TODO(gsagie) some of this checks are already implemented
        # in the base class, think how to avoid re-doing them
        if not self._is_this_snat_host():
            return

        sn_port = self.get_snat_port_for_internal_port(port)
        if not sn_port:
            return

        ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(self.router['id'])
        interface_name = self._get_snat_int_device_name(sn_port['id'])
        self._internal_network_added(
            ns_name,
            sn_port['network_id'],
            sn_port['id'],
            sn_port['fixed_ips'],
            sn_port['mac_address'],
            interface_name,
            lib_constants.SNAT_INT_DEV_PREFIX,
            mtu=sn_port.get('mtu'))

    def _dvr_internal_network_removed(self, port):
        super(DvrEdgeRouter, self)._dvr_internal_network_removed(port)

        if not self.ex_gw_port:
            return

        sn_port = self.get_snat_port_for_internal_port(port, self.snat_ports)
        if not sn_port:
            return

        if not self._is_this_snat_host():
            return

        snat_interface = self._get_snat_int_device_name(sn_port['id'])
        ns_name = self.snat_namespace.name
        prefix = lib_constants.SNAT_INT_DEV_PREFIX
        if ip_lib.device_exists(snat_interface, namespace=ns_name):
            self.driver.unplug(snat_interface, namespace=ns_name,
                               prefix=prefix)

    def _plug_snat_port(self, port):
        interface_name = self._get_snat_int_device_name(port['id'])
        self._internal_network_added(
            self.snat_namespace.name, port['network_id'],
            port['id'], port['fixed_ips'],
            port['mac_address'], interface_name,
            lib_constants.SNAT_INT_DEV_PREFIX,
            mtu=port.get('mtu'))

    def initialize(self, process_monitor):
        self._create_snat_namespace()
        super(DvrEdgeRouter, self).initialize(process_monitor)

    def _create_dvr_gateway(self, ex_gw_port, gw_interface_name):
        # connect snat_ports to br_int from SNAT namespace

        # NOTE(ataraday): Check if snat namespace exists, create if not -
        # workaround for race between router_added and router_updated
        # notifications https://launchpad.net/bugs/1881995
        if not self.snat_namespace.exists():
            self._create_snat_namespace()

        for port in self.get_snat_interfaces():
            self._plug_snat_port(port)
        self._external_gateway_added(ex_gw_port, gw_interface_name,
                                     self.snat_namespace.name,
                                     preserve_ips=[])
        self.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=self.snat_namespace.name,
            use_ipv6=self.use_ipv6)

        self._initialize_address_scope_iptables(self.snat_iptables_manager)

    def _create_snat_namespace(self):
        """Create SNAT namespace."""
        # TODO(mlavalle): in the near future, this method should contain the
        # code in the L3 agent that creates a gateway for a dvr. The first step
        # is to move the creation of the snat namespace here
        if self._is_this_snat_host():
            self.snat_namespace.create()

    def _get_snat_int_device_name(self, port_id):
        long_name = lib_constants.SNAT_INT_DEV_PREFIX + port_id
        return long_name[:self.driver.DEV_NAME_LEN]

    def _is_this_snat_host(self):
        host = self.router.get('gw_port_host')
        if not host:
            LOG.debug("gw_port_host missing from router: %s",
                      self.router['id'])
        return host == self.host

    def _handle_router_snat_rules(self, ex_gw_port, interface_name):
        super(DvrEdgeRouter, self)._handle_router_snat_rules(
            ex_gw_port, interface_name)

        if not self._is_this_snat_host():
            return
        if not self.get_ex_gw_port():
            return

        if not self.snat_iptables_manager:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        with self.snat_iptables_manager.defer_apply():
            self._empty_snat_chains(self.snat_iptables_manager)

            # NOTE: float-snat should be added for the
            # centralized floating-ips supported by the
            # snat namespace.
            self.snat_iptables_manager.ipv4['nat'].add_rule(
                'snat', '-j $float-snat')

            self._add_snat_rules(ex_gw_port, self.snat_iptables_manager,
                                 interface_name)

    def update_routing_table(self, operation, route):
        if self.get_ex_gw_port() and self._is_this_snat_host():
            ns_name = self.snat_namespace.name
            # NOTE: For now let us apply the static routes both in SNAT
            # namespace and Router Namespace, to reduce the complexity.
            if self.snat_namespace.exists():
                self._update_routing_table(operation, route, ns_name)
            else:
                LOG.error("The SNAT namespace %s does not exist for "
                          "the router.", ns_name)
        super(DvrEdgeRouter, self).update_routing_table(operation, route)

    def delete(self):
        super(DvrEdgeRouter, self).delete()
        if self.snat_namespace.exists():
            self.snat_namespace.delete()

    def process_address_scope(self):
        super(DvrEdgeRouter, self).process_address_scope()

        if not self._is_this_snat_host():
            return
        if not self.snat_iptables_manager:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        # Prepare address scope iptables rule for dvr snat interfaces
        internal_ports = self.get_snat_interfaces()
        ports_scopemark = self._get_port_devicename_scopemark(
            internal_ports, self._get_snat_int_device_name)
        # Prepare address scope iptables rule for external port
        external_port = self.get_ex_gw_port()
        if external_port:
            external_port_scopemark = self._get_port_devicename_scopemark(
                [external_port], self.get_external_device_name)
            for ip_version in (lib_constants.IP_VERSION_4,
                               lib_constants.IP_VERSION_6):
                ports_scopemark[ip_version].update(
                    external_port_scopemark[ip_version])

        with self.snat_iptables_manager.defer_apply():
            self._add_address_scope_mark(
                self.snat_iptables_manager, ports_scopemark)

    def _delete_stale_external_devices(self, interface_name):
        if not self.snat_namespace.exists():
            return

        ns_ip = ip_lib.IPWrapper(namespace=self.snat_namespace.name)
        for d in ns_ip.get_devices():
            if (d.name.startswith(router.EXTERNAL_DEV_PREFIX) and
                    d.name != interface_name):
                LOG.debug('Deleting stale external router device: %s', d.name)
                self.driver.unplug(
                    d.name,
                    namespace=self.snat_namespace.name,
                    prefix=router.EXTERNAL_DEV_PREFIX)

    def get_snat_external_device_interface_name(self, ex_gw_port):
        long_name = router.EXTERNAL_DEV_PREFIX + ex_gw_port['id']
        return long_name[:self.driver.DEV_NAME_LEN]

    def get_centralized_fip_cidr_set(self):
        """Returns the fip_cidr set for centralized floatingips."""
        ex_gw_port = self.get_ex_gw_port()
        # Don't look for centralized FIP cidrs if gw_port not exists or
        # this is not snat host
        if (not ex_gw_port or not self._is_this_snat_host() or
                not self.snat_namespace.exists()):
            return set()
        interface_name = self.get_snat_external_device_interface_name(
                ex_gw_port)
        return set([addr['cidr'] for addr in ip_lib.get_devices_with_ip(
                                                 self.snat_namespace.name,
                                                 name=interface_name)])

    def get_router_cidrs(self, device):
        """Over-ride the get_router_cidrs function to return the list.

        This function is overridden to provide the complete list of
        floating_ip cidrs that the router hosts.
        This includes the centralized floatingip cidr list and the
        regular floatingip cidr list that are bound to fip namespace.
        """
        fip_cidrs = super(DvrEdgeRouter, self).get_router_cidrs(device)
        centralized_cidrs = self.get_centralized_fip_cidr_set()
        return fip_cidrs | centralized_cidrs

    def remove_centralized_floatingip(self, fip_cidr):
        """Function to handle the centralized Floatingip remove."""
        if not self.get_ex_gw_port():
            return
        if not self._is_this_snat_host():
            return
        interface_name = self.get_snat_external_device_interface_name(
            self.get_ex_gw_port())
        device = ip_lib.IPDevice(
            interface_name, namespace=self.snat_namespace.name)
        device.delete_addr_and_conntrack_state(fip_cidr)
        self.process_floating_ip_nat_rules_for_centralized_floatingip()

    def add_centralized_floatingip(self, fip, fip_cidr):
        """Function to handle the centralized Floatingip addition."""
        if not self.get_ex_gw_port():
            return
        if not self._is_this_snat_host():
            return
        interface_name = self.get_snat_external_device_interface_name(
            self.get_ex_gw_port())
        try:
            ip_lib.add_ip_address(fip_cidr, interface_name,
                                  namespace=self.snat_namespace.name)
        except ip_lib.IpAddressAlreadyExists:
            pass
        except RuntimeError:
            LOG.warning("Unable to configure IP address for centralized "
                        "floating IP: %s", fip['id'])
            return lib_constants.FLOATINGIP_STATUS_ERROR
        self.process_floating_ip_nat_rules_for_centralized_floatingip()
        # Send a GARP message on the external interface for the
        # centralized floatingip configured.
        ip_lib.send_ip_addr_adv_notif(self.snat_namespace.name,
                                      interface_name,
                                      fip['floating_ip_address'])
        return lib_constants.FLOATINGIP_STATUS_ACTIVE

    def _centralized_floating_forward_rules(self, floating_ip, fixed_ip):
        to_source = '-s %s/32 -j SNAT --to-source %s' % (fixed_ip, floating_ip)
        if self.snat_iptables_manager.random_fully:
            to_source += ' --random-fully'
        return [('PREROUTING', '-d %s/32 -j DNAT --to-destination %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s/32 -j DNAT --to-destination %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', to_source)]

    def _set_floating_ip_nat_rules_for_centralized_floatingip(self, fip):
        if fip.get(lib_constants.DVR_SNAT_BOUND):
            fixed = fip['fixed_ip_address']
            fip_ip = fip['floating_ip_address']
            for chain, rule in self._centralized_floating_forward_rules(
                    fip_ip, fixed):
                self.snat_iptables_manager.ipv4['nat'].add_rule(
                    chain, rule, tag='floating_ip')

    def process_floating_ip_nat_rules_for_centralized_floatingip(self):
        self.snat_iptables_manager.ipv4['nat'].clear_rules_by_tag(
            'floating_ip')
        floating_ips = self.get_floating_ips()
        for fip in floating_ips:
            self._set_floating_ip_nat_rules_for_centralized_floatingip(fip)
        self.snat_iptables_manager.apply()

    def process_floating_ip_nat_rules(self):
        if self._is_this_snat_host():
            self.process_floating_ip_nat_rules_for_centralized_floatingip()

        # Cover mixed dvr_snat and compute node, aka a dvr_snat node has both
        # centralized and distributed floating IPs.
        super(DvrEdgeRouter, self).process_floating_ip_nat_rules()
