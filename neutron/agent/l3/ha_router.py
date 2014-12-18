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

import netaddr
import shutil
import signal

from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib
from neutron.agent.linux import keepalived
from neutron.agent.metadata import driver as metadata_driver
from neutron.common import utils as common_utils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)
HA_DEV_PREFIX = 'ha-'


class HaRouter(router.RouterInfo):
    def __init__(self, *args, **kwargs):
        super(HaRouter, self).__init__(*args, **kwargs)

        self.ha_port = None
        self.keepalived_manager = None

    def _verify_ha(self):
        # TODO(Carl) Remove when is_ha below is removed.
        if not self.is_ha:
            raise ValueError(_('Router %s is not a HA router') %
                             self.router_id)

    @property
    def is_ha(self):
        # TODO(Carl) Remove when refactoring to use sub-classes is complete.
        return self.router is not None

    @property
    def ha_priority(self):
        self._verify_ha()
        return self.router.get('priority', keepalived.HA_DEFAULT_PRIORITY)

    @property
    def ha_vr_id(self):
        self._verify_ha()
        return self.router.get('ha_vr_id')

    @property
    def ha_state(self):
        self._verify_ha()
        ha_state_path = self.keepalived_manager._get_full_config_file_path(
            'state')
        try:
            with open(ha_state_path, 'r') as f:
                return f.read()
        except (OSError, IOError):
            LOG.debug('Error while reading HA state for %s', self.router_id)
            return None

    def get_keepalived_manager(self):
        return keepalived.KeepalivedManager(
            self.router['id'],
            keepalived.KeepalivedConf(),
            conf_path=self.agent_conf.ha_confs_path,
            namespace=self.ns_name)

    def _init_keepalived_manager(self):
        # TODO(Carl) This looks a bit funny, doesn't it?
        self.keepalived_manager = self.get_keepalived_manager()

        config = self.keepalived_manager.config

        interface_name = self.get_ha_device_name(self.ha_port['id'])
        ha_port_cidr = self.ha_port['subnet']['cidr']
        instance = keepalived.KeepalivedInstance(
            'BACKUP',
            interface_name,
            self.ha_vr_id,
            ha_port_cidr,
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

    def spawn_keepalived(self):
        self.keepalived_manager.spawn_or_restart()

    def disable_keepalived(self):
        self.keepalived_manager.disable()
        conf_dir = self.keepalived_manager.get_conf_dir()
        shutil.rmtree(conf_dir)

    def _add_keepalived_notifiers(self):
        callback = (
            metadata_driver.MetadataDriver._get_metadata_proxy_callback(
                self.router_id, self.agent_conf))
        # TODO(mangelajo): use the process monitor in keepalived when
        #                  keepalived stops killing/starting metadata
        #                  proxy on its own
        pm = (
            metadata_driver.MetadataDriver.
            _get_metadata_proxy_process_manager(self.router_id,
                                                self.ns_name,
                                                self.agent_conf))
        pid = pm.get_pid_file_name()
        self.keepalived_manager.add_notifier(
            callback(pid), 'master', self.ha_vr_id)
        for state in ('backup', 'fault'):
            self.keepalived_manager.add_notifier(
                ['kill', '-%s' % signal.SIGKILL,
                 '$(cat ' + pid + ')'], state, self.ha_vr_id)

    def _get_keepalived_instance(self):
        return self.keepalived_manager.config.get_instance(self.ha_vr_id)

    def get_ha_device_name(self, port_id):
        return (HA_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def ha_network_added(self, network_id, port_id, internal_cidr,
                         mac_address):
        interface_name = self.get_ha_device_name(port_id)
        self.driver.plug(network_id, port_id, interface_name, mac_address,
                         namespace=self.ns_name,
                         prefix=HA_DEV_PREFIX)
        self.driver.init_l3(interface_name, [internal_cidr],
                            namespace=self.ns_name)

    def ha_network_removed(self):
        interface_name = self.get_ha_device_name(self.ha_port['id'])
        self.driver.unplug(interface_name, namespace=self.ns_name,
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

    def _ha_get_existing_cidrs(self, interface_name):
        instance = self._get_keepalived_instance()
        return instance.get_existing_vip_ip_addresses(interface_name)

    def get_router_cidrs(self, device):
        return set(self._ha_get_existing_cidrs(device.name))

    def _ha_external_gateway_removed(self, interface_name):
        self._clear_vips(interface_name)

    def routes_updated(self):
        new_routes = self.router['routes']

        instance = self._get_keepalived_instance()

        # Filter out all of the old routes while keeping only the default route
        instance.virtual_routes = [route for route in instance.virtual_routes
                                   if route.destination == '0.0.0.0/0']
        for route in new_routes:
            instance.virtual_routes.append(keepalived.KeepalivedVirtualRoute(
                route['destination'],
                route['nexthop']))

        self.routes = new_routes

    def _add_default_gw_virtual_route(self, ex_gw_port, interface_name):
        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if gw_ip:
            # TODO(Carl) This is repeated everywhere.  A method would be nice.
            instance = self._get_keepalived_instance()
            instance.virtual_routes = (
                [route for route in instance.virtual_routes
                 if route.destination != '0.0.0.0/0'])
            instance.virtual_routes.append(
                keepalived.KeepalivedVirtualRoute(
                    '0.0.0.0/0', gw_ip, interface_name))

    def _get_ipv6_lladdr(self, mac_addr):
        return '%s/64' % netaddr.EUI(mac_addr).ipv6_link_local()

    def _should_delete_ipv6_lladdr(self, ipv6_lladdr):
        """Only the master should have any IP addresses configured.
        Let keepalived manage IPv6 link local addresses, the same way we let
        it manage IPv4 addresses. In order to do that, we must delete
        the address first as it is autoconfigured by the kernel.
        """
        process = keepalived.KeepalivedManager.get_process(
            self.agent_conf,
            self.router_id,
            self.ns_name,
            self.agent_conf.ha_confs_path)
        if process.active:
            manager = self.get_keepalived_manager()
            conf = manager.get_conf_on_disk()
            managed_by_keepalived = conf and ipv6_lladdr in conf
            if managed_by_keepalived:
                return False
        return True

    def _ha_disable_addressing_on_interface(self, interface_name):
        """Disable IPv6 link local addressing on the device and add it as
        a VIP to keepalived. This means that the IPv6 link local address
        will only be present on the master.
        """
        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        ipv6_lladdr = self._get_ipv6_lladdr(device.link.address)

        if self._should_delete_ipv6_lladdr(ipv6_lladdr):
            device.addr.flush()

        self._remove_vip(ipv6_lladdr)
        self._add_vip(ipv6_lladdr, interface_name, scope='link')

    def _ha_external_gateway_added(self, ex_gw_port, interface_name):
        self._add_vip(ex_gw_port['ip_cidr'], interface_name)
        self._add_default_gw_virtual_route(ex_gw_port, interface_name)

    def _ha_external_gateway_updated(self, ex_gw_port, interface_name):
        old_gateway_cidr = self.ex_gw_port['ip_cidr']
        self._remove_vip(old_gateway_cidr)
        self._ha_external_gateway_added(ex_gw_port, interface_name)

    def add_floating_ip(self, fip, interface_name, device):
        fip_ip = fip['floating_ip_address']
        ip_cidr = common_utils.ip_to_cidr(fip_ip)
        self._add_vip(ip_cidr, interface_name)
        # TODO(Carl) Should this return status?
        # return l3_constants.FLOATINGIP_STATUS_ACTIVE

    def remove_floating_ip(self, device, ip_cidr):
        self._remove_vip(ip_cidr)
