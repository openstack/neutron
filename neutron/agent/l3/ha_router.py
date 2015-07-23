# Copyright (c) 2015 Openstack Foundation
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

import os
import shutil

import netaddr
from oslo_log import log as logging

from neutron.agent.l3 import router_info as router
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import keepalived
from neutron.common import constants as n_consts
from neutron.common import utils as common_utils
from neutron.i18n import _LE

LOG = logging.getLogger(__name__)
HA_DEV_PREFIX = 'ha-'
IP_MONITOR_PROCESS_SERVICE = 'ip_monitor'


class HaRouter(router.RouterInfo):
    def __init__(self, state_change_callback, *args, **kwargs):
        super(HaRouter, self).__init__(*args, **kwargs)

        self.ha_port = None
        self.keepalived_manager = None
        self.state_change_callback = state_change_callback

    @property
    def is_ha(self):
        # TODO(Carl) Remove when refactoring to use sub-classes is complete.
        return self.router is not None

    @property
    def ha_priority(self):
        return self.router.get('priority', keepalived.HA_DEFAULT_PRIORITY)

    @property
    def ha_vr_id(self):
        return self.router.get('ha_vr_id')

    @property
    def ha_state(self):
        ha_state_path = self.keepalived_manager.get_full_config_file_path(
            'state')
        try:
            with open(ha_state_path, 'r') as f:
                return f.read()
        except (OSError, IOError):
            LOG.debug('Error while reading HA state for %s', self.router_id)
            return None

    @ha_state.setter
    def ha_state(self, new_state):
        ha_state_path = self.keepalived_manager.get_full_config_file_path(
            'state')
        try:
            with open(ha_state_path, 'w') as f:
                f.write(new_state)
        except (OSError, IOError):
            LOG.error(_LE('Error while writing HA state for %s'),
                      self.router_id)

    def initialize(self, process_monitor):
        super(HaRouter, self).initialize(process_monitor)
        ha_port = self.router.get(n_consts.HA_INTERFACE_KEY)
        if not ha_port:
            LOG.error(_LE('Unable to process HA router %s without HA port'),
                      self.router_id)
            return

        self.ha_port = ha_port
        self._init_keepalived_manager(process_monitor)
        self.ha_network_added()
        self.update_initial_state(self.state_change_callback)
        self.spawn_state_change_monitor(process_monitor)

    def _init_keepalived_manager(self, process_monitor):
        self.keepalived_manager = keepalived.KeepalivedManager(
            self.router['id'],
            keepalived.KeepalivedConf(),
            process_monitor,
            conf_path=self.agent_conf.ha_confs_path,
            namespace=self.ns_name)

        config = self.keepalived_manager.config

        interface_name = self.get_ha_device_name()
        subnets = self.ha_port.get('subnets', [])
        ha_port_cidrs = [subnet['cidr'] for subnet in subnets]
        instance = keepalived.KeepalivedInstance(
            'BACKUP',
            interface_name,
            self.ha_vr_id,
            ha_port_cidrs,
            nopreempt=True,
            advert_int=self.agent_conf.ha_vrrp_advert_int,
            priority=self.ha_priority)
        instance.track_interfaces.append(interface_name)

        if self.agent_conf.ha_vrrp_auth_password:
            # TODO(safchain): use oslo.config types when it will be available
            # in order to check the validity of ha_vrrp_auth_type
            instance.set_authentication(self.agent_conf.ha_vrrp_auth_type,
                                        self.agent_conf.ha_vrrp_auth_password)

        config.add_instance(instance)

    def enable_keepalived(self):
        self.keepalived_manager.spawn()

    def disable_keepalived(self):
        self.keepalived_manager.disable()
        conf_dir = self.keepalived_manager.get_conf_dir()
        shutil.rmtree(conf_dir)

    def _get_keepalived_instance(self):
        return self.keepalived_manager.config.get_instance(self.ha_vr_id)

    def _get_primary_vip(self):
        return self._get_keepalived_instance().get_primary_vip()

    def get_ha_device_name(self):
        return (HA_DEV_PREFIX + self.ha_port['id'])[:self.driver.DEV_NAME_LEN]

    def ha_network_added(self):
        interface_name = self.get_ha_device_name()

        self.driver.plug(self.ha_port['network_id'],
                         self.ha_port['id'],
                         interface_name,
                         self.ha_port['mac_address'],
                         namespace=self.ns_name,
                         prefix=HA_DEV_PREFIX)
        ip_cidrs = common_utils.fixed_ip_cidrs(self.ha_port['fixed_ips'])
        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=self.ns_name,
                            preserve_ips=[self._get_primary_vip()])

    def ha_network_removed(self):
        self.driver.unplug(self.get_ha_device_name(),
                           namespace=self.ns_name,
                           prefix=HA_DEV_PREFIX)
        self.ha_port = None

    def _add_vip(self, ip_cidr, interface, scope=None):
        instance = self._get_keepalived_instance()
        instance.add_vip(ip_cidr, interface, scope)

    def _remove_vip(self, ip_cidr):
        instance = self._get_keepalived_instance()
        instance.remove_vip_by_ip_address(ip_cidr)

    def _clear_vips(self, interface):
        instance = self._get_keepalived_instance()
        instance.remove_vips_vroutes_by_interface(interface)

    def _get_cidrs_from_keepalived(self, interface_name):
        instance = self._get_keepalived_instance()
        return instance.get_existing_vip_ip_addresses(interface_name)

    def get_router_cidrs(self, device):
        return set(self._get_cidrs_from_keepalived(device.name))

    def routes_updated(self):
        new_routes = self.router['routes']

        instance = self._get_keepalived_instance()
        instance.virtual_routes.extra_routes = [
            keepalived.KeepalivedVirtualRoute(
                route['destination'], route['nexthop'])
            for route in new_routes]
        self.routes = new_routes

    def _add_default_gw_virtual_route(self, ex_gw_port, interface_name):
        default_gw_rts = []
        gateway_ips, enable_ra_on_gw = self._get_external_gw_ips(ex_gw_port)
        for gw_ip in gateway_ips:
                # TODO(Carl) This is repeated everywhere.  A method would
                # be nice.
                default_gw = n_consts.IP_ANY[netaddr.IPAddress(gw_ip).version]
                instance = self._get_keepalived_instance()
                default_gw_rts.append(keepalived.KeepalivedVirtualRoute(
                    default_gw, gw_ip, interface_name))
        instance.virtual_routes.gateway_routes = default_gw_rts

        if enable_ra_on_gw:
            self.driver.configure_ipv6_ra(self.ns_name, interface_name)

    def _add_extra_subnet_onlink_routes(self, ex_gw_port, interface_name):
        extra_subnets = ex_gw_port.get('extra_subnets', [])
        instance = self._get_keepalived_instance()
        onlink_route_cidrs = set(s['cidr'] for s in extra_subnets)
        instance.virtual_routes.extra_subnets = [
            keepalived.KeepalivedVirtualRoute(
                onlink_route_cidr, None, interface_name, scope='link') for
            onlink_route_cidr in onlink_route_cidrs]

    def _should_delete_ipv6_lladdr(self, ipv6_lladdr):
        """Only the master should have any IP addresses configured.
        Let keepalived manage IPv6 link local addresses, the same way we let
        it manage IPv4 addresses. If the router is not in the master state,
        we must delete the address first as it is autoconfigured by the kernel.
        """
        manager = self.keepalived_manager
        if manager.get_process().active:
            if self.ha_state != 'master':
                conf = manager.get_conf_on_disk()
                managed_by_keepalived = conf and ipv6_lladdr in conf
                if managed_by_keepalived:
                    return False
            else:
                return False
        return True

    def _disable_ipv6_addressing_on_interface(self, interface_name):
        """Disable IPv6 link local addressing on the device and add it as
        a VIP to keepalived. This means that the IPv6 link local address
        will only be present on the master.
        """
        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        ipv6_lladdr = ip_lib.get_ipv6_lladdr(device.link.address)

        if self._should_delete_ipv6_lladdr(ipv6_lladdr):
            device.addr.flush(n_consts.IP_VERSION_6)

        self._remove_vip(ipv6_lladdr)
        self._add_vip(ipv6_lladdr, interface_name, scope='link')

    def _add_gateway_vip(self, ex_gw_port, interface_name):
        for ip_cidr in common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips']):
            self._add_vip(ip_cidr, interface_name)
        self._add_default_gw_virtual_route(ex_gw_port, interface_name)
        self._add_extra_subnet_onlink_routes(ex_gw_port, interface_name)

    def add_floating_ip(self, fip, interface_name, device):
        fip_ip = fip['floating_ip_address']
        ip_cidr = common_utils.ip_to_cidr(fip_ip)
        self._add_vip(ip_cidr, interface_name)
        # TODO(Carl) Should this return status?
        # return l3_constants.FLOATINGIP_STATUS_ACTIVE

    def remove_floating_ip(self, device, ip_cidr):
        self._remove_vip(ip_cidr)

    def internal_network_updated(self, interface_name, ip_cidrs):
        self._clear_vips(interface_name)
        self._disable_ipv6_addressing_on_interface(interface_name)
        for ip_cidr in ip_cidrs:
            self._add_vip(ip_cidr, interface_name)

    def internal_network_added(self, port):
        port_id = port['id']
        interface_name = self.get_internal_device_name(port_id)

        self.driver.plug(port['network_id'],
                         port_id,
                         interface_name,
                         port['mac_address'],
                         namespace=self.ns_name,
                         prefix=router.INTERNAL_DEV_PREFIX)

        self._disable_ipv6_addressing_on_interface(interface_name)
        for ip_cidr in common_utils.fixed_ip_cidrs(port['fixed_ips']):
            self._add_vip(ip_cidr, interface_name)

    def internal_network_removed(self, port):
        super(HaRouter, self).internal_network_removed(port)

        interface_name = self.get_internal_device_name(port['id'])
        self._clear_vips(interface_name)

    def _get_state_change_monitor_process_manager(self):
        return external_process.ProcessManager(
            self.agent_conf,
            '%s.monitor' % self.router_id,
            self.ns_name,
            default_cmd_callback=self._get_state_change_monitor_callback())

    def _get_state_change_monitor_callback(self):
        ha_device = self.get_ha_device_name()
        ha_cidr = self._get_primary_vip()

        def callback(pid_file):
            cmd = [
                'neutron-keepalived-state-change',
                '--router_id=%s' % self.router_id,
                '--namespace=%s' % self.ns_name,
                '--conf_dir=%s' % self.keepalived_manager.get_conf_dir(),
                '--monitor_interface=%s' % ha_device,
                '--monitor_cidr=%s' % ha_cidr,
                '--pid_file=%s' % pid_file,
                '--state_path=%s' % self.agent_conf.state_path,
                '--user=%s' % os.geteuid(),
                '--group=%s' % os.getegid()]
            return cmd

        return callback

    def spawn_state_change_monitor(self, process_monitor):
        pm = self._get_state_change_monitor_process_manager()
        pm.enable()
        process_monitor.register(
            self.router_id, IP_MONITOR_PROCESS_SERVICE, pm)

    def destroy_state_change_monitor(self, process_monitor):
        pm = self._get_state_change_monitor_process_manager()
        process_monitor.unregister(
            self.router_id, IP_MONITOR_PROCESS_SERVICE)
        pm.disable()

    def update_initial_state(self, callback):
        ha_device = ip_lib.IPDevice(
            self.get_ha_device_name(),
            self.ns_name)
        addresses = ha_device.addr.list()
        cidrs = (address['cidr'] for address in addresses)
        ha_cidr = self._get_primary_vip()
        state = 'master' if ha_cidr in cidrs else 'backup'
        self.ha_state = state
        callback(self.router_id, state)

    def external_gateway_added(self, ex_gw_port, interface_name):
        self._plug_external_gateway(ex_gw_port, interface_name, self.ns_name)
        self._add_gateway_vip(ex_gw_port, interface_name)
        self._disable_ipv6_addressing_on_interface(interface_name)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        self._plug_external_gateway(ex_gw_port, interface_name, self.ns_name)
        ip_cidrs = common_utils.fixed_ip_cidrs(self.ex_gw_port['fixed_ips'])
        for old_gateway_cidr in ip_cidrs:
            self._remove_vip(old_gateway_cidr)
        self._add_gateway_vip(ex_gw_port, interface_name)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        self._clear_vips(interface_name)

        super(HaRouter, self).external_gateway_removed(ex_gw_port,
                                                       interface_name)

    def delete(self, agent):
        self.destroy_state_change_monitor(self.process_monitor)
        self.ha_network_removed()
        self.disable_keepalived()
        super(HaRouter, self).delete(agent)

    def process(self, agent):
        super(HaRouter, self).process(agent)

        if self.ha_port:
            self.enable_keepalived()

    @common_utils.synchronized('enable_radvd')
    def enable_radvd(self, internal_ports=None):
        if (self.keepalived_manager.get_process().active and
                self.ha_state == 'master'):
            super(HaRouter, self).enable_radvd(internal_ports)
