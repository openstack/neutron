# Copyright (c) 2014 OpenStack Foundation.
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

import os
import signal

import netaddr
from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import keepalived
from neutron.agent.metadata import driver as metadata_driver
from neutron.common import constants as l3_constants
from neutron.i18n import _LE
from neutron.openstack.common import log as logging
from neutron.openstack.common import periodic_task

LOG = logging.getLogger(__name__)

HA_DEV_PREFIX = 'ha-'

OPTS = [
    cfg.StrOpt('ha_confs_path',
               default='$state_path/ha_confs',
               help=_('Location to store keepalived/conntrackd '
                      'config files')),
    cfg.StrOpt('ha_vrrp_auth_type',
               default='PASS',
               help=_('VRRP authentication type AH/PASS')),
    cfg.StrOpt('ha_vrrp_auth_password',
               help=_('VRRP authentication password'),
               secret=True),
    cfg.IntOpt('ha_vrrp_advert_int',
               default=2,
               help=_('The advertisement interval in seconds')),
]


class AgentMixin(object):
    def __init__(self, host):
        self._init_ha_conf_path()
        super(AgentMixin, self).__init__(host)

    def _init_ha_conf_path(self):
        ha_full_path = os.path.dirname("/%s/" % self.conf.ha_confs_path)
        if not os.path.isdir(ha_full_path):
            os.makedirs(ha_full_path, 0o755)

    def get_keepalived_manager(self, ri):
        return keepalived.KeepalivedManager(
            ri.router['id'],
            keepalived.KeepalivedConf(),
            conf_path=self.conf.ha_confs_path,
            namespace=ri.ns_name,
            root_helper=self.root_helper)

    def _init_keepalived_manager(self, ri):
        ri.keepalived_manager = self.get_keepalived_manager(ri)

        config = ri.keepalived_manager.config

        interface_name = self.get_ha_device_name(ri.ha_port['id'])
        ha_port_cidr = ri.ha_port['subnet']['cidr']
        instance = keepalived.KeepalivedInstance(
            'BACKUP', interface_name, ri.ha_vr_id, ha_port_cidr,
            nopreempt=True, advert_int=self.conf.ha_vrrp_advert_int,
            priority=ri.ha_priority)
        instance.track_interfaces.append(interface_name)

        if self.conf.ha_vrrp_auth_password:
            # TODO(safchain): use oslo.config types when it will be available
            # in order to check the validity of ha_vrrp_auth_type
            instance.set_authentication(self.conf.ha_vrrp_auth_type,
                                        self.conf.ha_vrrp_auth_password)

        group = keepalived.KeepalivedGroup(ri.ha_vr_id)
        group.add_instance(instance)

        config.add_group(group)
        config.add_instance(instance)

    def process_ha_router_added(self, ri):
        ha_port = ri.router.get(l3_constants.HA_INTERFACE_KEY)
        if not ha_port:
            LOG.error(_LE('Unable to process HA router %s without ha port'),
                      ri.router_id)
            return

        self._set_subnet_info(ha_port)
        self.ha_network_added(ri, ha_port['network_id'], ha_port['id'],
                              ha_port['ip_cidr'], ha_port['mac_address'])
        ri.ha_port = ha_port

        self._init_keepalived_manager(ri)
        self._add_keepalived_notifiers(ri)

    def process_ha_router_removed(self, ri):
        self.ha_network_removed(ri)

    def get_ha_device_name(self, port_id):
        return (HA_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def ha_network_added(self, ri, network_id, port_id, internal_cidr,
                         mac_address):
        interface_name = self.get_ha_device_name(port_id)
        self.driver.plug(network_id, port_id, interface_name, mac_address,
                         namespace=ri.ns_name,
                         prefix=HA_DEV_PREFIX)
        self.driver.init_l3(interface_name, [internal_cidr],
                            namespace=ri.ns_name)

    def ha_network_removed(self, ri):
        interface_name = self.get_ha_device_name(ri.ha_port['id'])
        self.driver.unplug(interface_name, namespace=ri.ns_name,
                           prefix=HA_DEV_PREFIX)
        ri.ha_port = None

    def _add_vip(self, ri, ip_cidr, interface, scope=None):
        instance = ri.keepalived_manager.config.get_instance(ri.ha_vr_id)
        instance.add_vip(ip_cidr, interface, scope)

    def _remove_vip(self, ri, ip_cidr):
        instance = ri.keepalived_manager.config.get_instance(ri.ha_vr_id)
        instance.remove_vip_by_ip_address(ip_cidr)

    def _clear_vips(self, ri, interface):
        instance = ri.keepalived_manager.config.get_instance(ri.ha_vr_id)
        instance.remove_vips_vroutes_by_interface(interface)

    def _ha_get_existing_cidrs(self, ri, interface_name):
        instance = ri.keepalived_manager.config.get_instance(ri.ha_vr_id)
        return instance.get_existing_vip_ip_addresses(interface_name)

    def _add_keepalived_notifiers(self, ri):
        callback = (
            metadata_driver.MetadataDriver._get_metadata_proxy_callback(
                ri.router_id, self.conf))
        pm = (
            metadata_driver.MetadataDriver.
            _get_metadata_proxy_process_manager(ri.router_id,
                                                ri.ns_name,
                                                self.conf))
        pid = pm.get_pid_file_name(ensure_pids_dir=True)
        ri.keepalived_manager.add_notifier(
            callback(pid), 'master', ri.ha_vr_id)
        for state in ('backup', 'fault'):
            ri.keepalived_manager.add_notifier(
                ['kill', '-%s' % signal.SIGKILL,
                 '$(cat ' + pid + ')'], state, ri.ha_vr_id)

    def _ha_external_gateway_updated(self, ri, ex_gw_port, interface_name):
        old_gateway_cidr = ri.ex_gw_port['ip_cidr']
        self._remove_vip(ri, old_gateway_cidr)
        self._ha_external_gateway_added(ri, ex_gw_port, interface_name)

    def _add_default_gw_virtual_route(self, ri, ex_gw_port, interface_name):
        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if gw_ip:
            instance = ri.keepalived_manager.config.get_instance(ri.ha_vr_id)
            instance.virtual_routes = (
                [route for route in instance.virtual_routes
                 if route.destination != '0.0.0.0/0'])
            instance.virtual_routes.append(
                keepalived.KeepalivedVirtualRoute(
                    '0.0.0.0/0', gw_ip, interface_name))

    def _ha_external_gateway_added(self, ri, ex_gw_port, interface_name):
        self._add_vip(ri, ex_gw_port['ip_cidr'], interface_name)
        self._add_default_gw_virtual_route(ri, ex_gw_port, interface_name)

    def _should_delete_ipv6_lladdr(self, ri, ipv6_lladdr):
        """Only the master should have any IP addresses configured.
        Let keepalived manage IPv6 link local addresses, the same way we let
        it manage IPv4 addresses. In order to do that, we must delete
        the address first as it is autoconfigured by the kernel.
        """
        process = keepalived.KeepalivedManager.get_process(
            self.conf,
            ri.router_id,
            self.root_helper,
            ri.ns_name,
            self.conf.ha_confs_path)
        if process.active:
            manager = self.get_keepalived_manager(ri)
            conf = manager.get_conf_on_disk()
            managed_by_keepalived = conf and ipv6_lladdr in conf
            if managed_by_keepalived:
                return False
        return True

    def _ha_disable_addressing_on_interface(self, ri, interface_name):
        """Disable IPv6 link local addressing on the device and add it as
        a VIP to keepalived. This means that the IPv6 link local address
        will only be present on the master.
        """
        device = ip_lib.IPDevice(interface_name, self.root_helper, ri.ns_name)
        ipv6_lladdr = self._get_ipv6_lladdr(device.link.address)

        if self._should_delete_ipv6_lladdr(ri, ipv6_lladdr):
            device.addr.flush()

        self._remove_vip(ri, ipv6_lladdr)
        self._add_vip(ri, ipv6_lladdr, interface_name, scope='link')

    def _get_ipv6_lladdr(self, mac_addr):
        return '%s/64' % netaddr.EUI(mac_addr).ipv6_link_local()

    def _ha_external_gateway_removed(self, ri, interface_name):
        self._clear_vips(ri, interface_name)

    def _process_virtual_routes(self, ri, new_routes):
        instance = ri.keepalived_manager.config.get_instance(ri.ha_vr_id)

        # Filter out all of the old routes while keeping only the default route
        instance.virtual_routes = [route for route in instance.virtual_routes
                                   if route.destination == '0.0.0.0/0']
        for route in new_routes:
            instance.virtual_routes.append(keepalived.KeepalivedVirtualRoute(
                route['destination'],
                route['nexthop']))

    def get_ha_routers(self):
        return (router for router in self.router_info.values() if router.is_ha)

    @periodic_task.periodic_task
    def _ensure_keepalived_alive(self, context):
        # TODO(amuller): Use external_process.ProcessMonitor
        for router in self.get_ha_routers():
            router.keepalived_manager.revive()
