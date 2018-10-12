# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
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

from neutron_lib import constants

from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import ha_router
from neutron.agent.l3 import router_info


class DvrEdgeHaRouter(dvr_edge_router.DvrEdgeRouter,
                      ha_router.HaRouter):
    """Router class which represents a centralized SNAT
       DVR router with HA capabilities.
    """

    def __init__(self, host, *args, **kwargs):
        super(DvrEdgeHaRouter, self).__init__(host,
                                              *args, **kwargs)
        self.enable_snat = None

    @property
    def ha_namespace(self):
        if self.snat_namespace:
            return self.snat_namespace.name
        return None

    def internal_network_added(self, port):
        # Call RouterInfo's internal_network_added (Plugs the port, adds IP)
        router_info.RouterInfo.internal_network_added(self, port)

        for subnet in port['subnets']:
            self._set_subnet_arp_info(subnet['id'])
        self._snat_redirect_add_from_port(port)

        if not self.get_ex_gw_port() or not self._is_this_snat_host():
            return

        sn_port = self.get_snat_port_for_internal_port(port)
        if not sn_port:
            return

        self._plug_ha_router_port(
            sn_port,
            self._get_snat_int_device_name,
            constants.SNAT_INT_DEV_PREFIX)

    def add_centralized_floatingip(self, fip, fip_cidr):
        interface_name = self.get_snat_external_device_interface_name(
                self.get_ex_gw_port())
        self._add_vip(fip_cidr, interface_name)

        self.ha_port = self.router.get(constants.HA_INTERFACE_KEY)
        if (self.is_router_master() and self.ha_port and
                self.ha_port['status'] == constants.PORT_STATUS_ACTIVE):
            return super(DvrEdgeHaRouter, self).add_centralized_floatingip(
                fip, fip_cidr)
        else:
            return constants.FLOATINGIP_STATUS_ACTIVE

    def remove_centralized_floatingip(self, fip_cidr):
        self._remove_vip(fip_cidr)
        if self.is_router_master():
            super(DvrEdgeHaRouter, self).remove_centralized_floatingip(
                fip_cidr)

    def get_centralized_fip_cidr_set(self):
        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return set()
        interface_name = self.get_snat_external_device_interface_name(
            ex_gw_port)
        return set(self._get_cidrs_from_keepalived(interface_name))

    def external_gateway_added(self, ex_gw_port, interface_name):
        super(DvrEdgeHaRouter, self).external_gateway_added(
            ex_gw_port, interface_name)
        for port in self.get_snat_interfaces():
            snat_interface_name = self._get_snat_int_device_name(port['id'])
            self._disable_ipv6_addressing_on_interface(snat_interface_name)
            self._add_vips(
                self.get_snat_port_for_internal_port(port),
                snat_interface_name)

        self._add_gateway_vip(ex_gw_port, interface_name)
        self._disable_ipv6_addressing_on_interface(interface_name)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        for port in self.snat_ports:
            snat_interface = self._get_snat_int_device_name(port['id'])
            self.driver.unplug(snat_interface,
                               namespace=self.ha_namespace,
                               prefix=constants.SNAT_INT_DEV_PREFIX)
            self._clear_vips(snat_interface)
        super(DvrEdgeHaRouter, self)._external_gateway_removed(
            ex_gw_port, interface_name)
        self._clear_vips(interface_name)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        ha_router.HaRouter.external_gateway_updated(self, ex_gw_port,
                                                    interface_name)

    def initialize(self, process_monitor):
        self._create_snat_namespace()
        super(DvrEdgeHaRouter, self).initialize(process_monitor)

    def _external_gateway_added(self, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        self._plug_external_gateway(ex_gw_port, interface_name, ns_name)

    def _is_this_snat_host(self):
        return self.agent_conf.agent_mode == constants.L3_AGENT_MODE_DVR_SNAT

    def _dvr_internal_network_removed(self, port):
        super(DvrEdgeHaRouter, self)._dvr_internal_network_removed(port)
        sn_port = self.get_snat_port_for_internal_port(port, self.snat_ports)
        if not sn_port:
            return
        self._clear_vips(self._get_snat_int_device_name(sn_port['id']))

    def _plug_snat_port(self, port):
        """Used by _create_dvr_gateway in DvrEdgeRouter."""
        interface_name = self._get_snat_int_device_name(port['id'])
        self.driver.plug(port['network_id'], port['id'],
                         interface_name, port['mac_address'],
                         namespace=self.snat_namespace.name,
                         prefix=constants.SNAT_INT_DEV_PREFIX,
                         mtu=port.get('mtu'))
