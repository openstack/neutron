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

import os
import shutil
import signal

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_consts
from neutron_lib.utils import runtime
from oslo_log import log as logging

from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import keepalived
from neutron.common import constants as const
from neutron.common import utils as common_utils
from neutron.extensions import revisions
from neutron.extensions import timestamp

LOG = logging.getLogger(__name__)
HA_DEV_PREFIX = 'ha-'
IP_MONITOR_PROCESS_SERVICE = 'ip_monitor'
SIGTERM_TIMEOUT = 10

# The multiplier is used to compensate execution time of function sending
# SIGHUP to keepalived process. The constant multiplies ha_vrrp_advert_int
# config option and the result is the throttle delay.
THROTTLER_MULTIPLIER = 1.5


class HaRouterNamespace(namespaces.RouterNamespace):
    """Namespace for HA router.

    This namespace sets the ip_nonlocal_bind to 0 for HA router namespaces.
    It does so to prevent sending gratuitous ARPs for interfaces that got VIP
    removed in the middle of processing.
    It also disables ipv6 forwarding by default. Forwarding will be
    enabled during router configuration processing only for the master node.
    It has to be disabled on all other nodes to avoid sending MLD packets
    which cause lost connectivity to Floating IPs.
    """
    def create(self):
        super(HaRouterNamespace, self).create(ipv6_forwarding=False)
        # HA router namespaces should not have ip_nonlocal_bind enabled
        ip_lib.set_ip_nonlocal_bind_for_namespace(self.name, 0)


class HaRouter(router.RouterInfo):
    def __init__(self, state_change_callback, *args, **kwargs):
        super(HaRouter, self).__init__(*args, **kwargs)

        self.ha_port = None
        self.keepalived_manager = None
        self.state_change_callback = state_change_callback

    def create_router_namespace_object(
            self, router_id, agent_conf, iface_driver, use_ipv6):
        return HaRouterNamespace(
            router_id, agent_conf, iface_driver, use_ipv6)

    @property
    def ha_priority(self):
        return self.router.get('priority', keepalived.HA_DEFAULT_PRIORITY)

    @property
    def ha_vr_id(self):
        return self.router.get('ha_vr_id')

    @property
    def ha_state(self):
        state = None
        ha_state_path = self.keepalived_manager.get_full_config_file_path(
            'state')
        try:
            with open(ha_state_path, 'r') as f:
                state = f.read()
        except (OSError, IOError):
            LOG.debug('Error while reading HA state for %s', self.router_id)
        return state or 'unknown'

    @ha_state.setter
    def ha_state(self, new_state):
        ha_state_path = self.keepalived_manager.get_full_config_file_path(
            'state')
        try:
            with open(ha_state_path, 'w') as f:
                f.write(new_state)
        except (OSError, IOError):
            LOG.error('Error while writing HA state for %s',
                      self.router_id)

    @property
    def ha_namespace(self):
        return self.ns_name

    def is_router_master(self):
        """this method is normally called before the ha_router object is fully
        initialized
        """
        if self.router.get('_ha_state') == 'active':
            return True
        else:
            return False

    def initialize(self, process_monitor):
        ha_port = self.router.get(n_consts.HA_INTERFACE_KEY)
        if not ha_port:
            msg = ("Unable to process HA router %s without HA port" %
                   self.router_id)
            LOG.exception(msg)
            raise Exception(msg)
        super(HaRouter, self).initialize(process_monitor)

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
            namespace=self.ha_namespace,
            throttle_restart_value=(
                self.agent_conf.ha_vrrp_advert_int * THROTTLER_MULTIPLIER))

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
            priority=self.ha_priority,
            vrrp_health_check_interval=(
                self.agent_conf.ha_vrrp_health_check_interval),
            ha_conf_dir=self.keepalived_manager.get_conf_dir())
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
        if not self.keepalived_manager:
            LOG.debug('Error while disabling keepalived for %s - no manager',
                      self.router_id)
            return
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
                         namespace=self.ha_namespace,
                         prefix=HA_DEV_PREFIX,
                         mtu=self.ha_port.get('mtu'))
        ip_cidrs = common_utils.fixed_ip_cidrs(self.ha_port['fixed_ips'])
        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=self.ha_namespace,
                            preserve_ips=[self._get_primary_vip()])

    def ha_network_removed(self):
        if not self.ha_port:
            LOG.debug('Error while removing HA network for %s - no port',
                      self.router_id)
            return
        self.driver.unplug(self.get_ha_device_name(),
                           namespace=self.ha_namespace,
                           prefix=HA_DEV_PREFIX)
        self.ha_port = None

    def _add_vips(self, port, interface_name):
        for ip_cidr in common_utils.fixed_ip_cidrs(port['fixed_ips']):
            self._add_vip(ip_cidr, interface_name)

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

    def routes_updated(self, old_routes, new_routes):
        instance = self._get_keepalived_instance()
        instance.virtual_routes.extra_routes = [
            keepalived.KeepalivedVirtualRoute(
                route['destination'], route['nexthop'])
            for route in new_routes]
        super(HaRouter, self).routes_updated(old_routes, new_routes)

    def _add_default_gw_virtual_route(self, ex_gw_port, interface_name):
        gateway_ips = self._get_external_gw_ips(ex_gw_port)

        default_gw_rts = []
        instance = self._get_keepalived_instance()
        for gw_ip in gateway_ips:
            # TODO(Carl) This is repeated everywhere.  A method would
            # be nice.
            default_gw = n_consts.IP_ANY[netaddr.IPAddress(gw_ip).version]
            default_gw_rts.append(keepalived.KeepalivedVirtualRoute(
                default_gw, gw_ip, interface_name))
        instance.virtual_routes.gateway_routes = default_gw_rts

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
        device = ip_lib.IPDevice(interface_name, namespace=self.ha_namespace)
        ipv6_lladdr = ip_lib.get_ipv6_lladdr(device.link.address)

        if self._should_delete_ipv6_lladdr(ipv6_lladdr):
            self.driver.configure_ipv6_ra(self.ha_namespace, interface_name,
                                          const.ACCEPT_RA_DISABLED)
            device.addr.flush(n_consts.IP_VERSION_6)
        else:
            self.driver.configure_ipv6_ra(self.ha_namespace, interface_name,
                                          const.ACCEPT_RA_WITHOUT_FORWARDING)

        self._remove_vip(ipv6_lladdr)
        self._add_vip(ipv6_lladdr, interface_name, scope='link')

    def _add_gateway_vip(self, ex_gw_port, interface_name):
        self._add_vips(ex_gw_port, interface_name)
        self._add_default_gw_virtual_route(ex_gw_port, interface_name)
        self._add_extra_subnet_onlink_routes(ex_gw_port, interface_name)

    def add_floating_ip(self, fip, interface_name, device):
        fip_ip = fip['floating_ip_address']
        ip_cidr = common_utils.ip_to_cidr(fip_ip)
        self._add_vip(ip_cidr, interface_name)
        return n_consts.FLOATINGIP_STATUS_ACTIVE

    def remove_floating_ip(self, device, ip_cidr):
        self._remove_vip(ip_cidr)
        to = common_utils.cidr_to_ip(ip_cidr)
        if device.addr.list(to=to):
            super(HaRouter, self).remove_floating_ip(device, ip_cidr)

    def internal_network_updated(self, interface_name, ip_cidrs, mtu):
        self.driver.set_mtu(interface_name, mtu, namespace=self.ns_name,
                            prefix=router.INTERNAL_DEV_PREFIX)
        self._clear_vips(interface_name)
        self._disable_ipv6_addressing_on_interface(interface_name)
        for ip_cidr in ip_cidrs:
            self._add_vip(ip_cidr, interface_name)

    def _plug_ha_router_port(self, port, name_getter, prefix):
        port_id = port['id']
        interface_name = name_getter(port_id)
        self.driver.plug(port['network_id'],
                         port_id,
                         interface_name,
                         port['mac_address'],
                         namespace=self.ha_namespace,
                         prefix=prefix,
                         mtu=port.get('mtu'))

        self._disable_ipv6_addressing_on_interface(interface_name)
        self._add_vips(port, interface_name)

    def internal_network_added(self, port):
        self._plug_ha_router_port(
            port, self.get_internal_device_name, router.INTERNAL_DEV_PREFIX)

    def internal_network_removed(self, port):
        super(HaRouter, self).internal_network_removed(port)

        interface_name = self.get_internal_device_name(port['id'])
        self._clear_vips(interface_name)

    def _get_state_change_monitor_process_manager(self):
        return external_process.ProcessManager(
            self.agent_conf,
            '%s.monitor' % self.router_id,
            self.ha_namespace,
            default_cmd_callback=self._get_state_change_monitor_callback())

    def _get_state_change_monitor_callback(self):
        ha_device = self.get_ha_device_name()
        ha_cidr = self._get_primary_vip()

        def callback(pid_file):
            cmd = [
                'neutron-keepalived-state-change',
                '--router_id=%s' % self.router_id,
                '--namespace=%s' % self.ha_namespace,
                '--conf_dir=%s' % self.keepalived_manager.get_conf_dir(),
                '--monitor_interface=%s' % ha_device,
                '--monitor_cidr=%s' % ha_cidr,
                '--pid_file=%s' % pid_file,
                '--state_path=%s' % self.agent_conf.state_path,
                '--user=%s' % os.geteuid(),
                '--group=%s' % os.getegid(),
                '--AGENT-root_helper=%s' % self.agent_conf.AGENT.root_helper,
                '--AGENT-root_helper_daemon=%s' %
                self.agent_conf.AGENT.root_helper_daemon]
            return cmd

        return callback

    def spawn_state_change_monitor(self, process_monitor):
        pm = self._get_state_change_monitor_process_manager()
        pm.enable()
        process_monitor.register(
            self.router_id, IP_MONITOR_PROCESS_SERVICE, pm)

    def destroy_state_change_monitor(self, process_monitor):
        if not self.ha_port:
            LOG.debug('Error while destroying state change monitor for %s - '
                      'no port', self.router_id)
            return
        pm = self._get_state_change_monitor_process_manager()
        process_monitor.unregister(
            self.router_id, IP_MONITOR_PROCESS_SERVICE)
        pm.disable(sig=str(int(signal.SIGTERM)))
        try:
            common_utils.wait_until_true(lambda: not pm.active,
                                         timeout=SIGTERM_TIMEOUT)
        except common_utils.WaitTimeout:
            pm.disable(sig=str(int(signal.SIGKILL)))

    def update_initial_state(self, callback):
        addresses = ip_lib.get_devices_with_ip(self.ha_namespace,
                                               name=self.get_ha_device_name())
        cidrs = (address['cidr'] for address in addresses)
        ha_cidr = self._get_primary_vip()
        state = 'master' if ha_cidr in cidrs else 'backup'
        self.ha_state = state
        callback(self.router_id, state)

    @staticmethod
    def _gateway_ports_equal(port1, port2):
        def _get_filtered_dict(d, ignore):
            return {k: v for k, v in d.items() if k not in ignore}

        keys_to_ignore = set([portbindings.HOST_ID, timestamp.UPDATED,
                              revisions.REVISION])
        port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
        port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
        return port1_filtered == port2_filtered

    def external_gateway_added(self, ex_gw_port, interface_name):
        self._plug_external_gateway(ex_gw_port, interface_name, self.ns_name)
        self._add_gateway_vip(ex_gw_port, interface_name)
        self._disable_ipv6_addressing_on_interface(interface_name)

        # Enable RA and IPv6 forwarding only for master instances. This will
        # prevent backup routers from sending packets to the upstream switch
        # and disrupt connections.
        enable = self.ha_state == 'master'
        self._configure_ipv6_params_on_gw(ex_gw_port, self.ns_name,
                                          interface_name, enable)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        self._plug_external_gateway(
            ex_gw_port, interface_name, self.ha_namespace)
        ip_cidrs = common_utils.fixed_ip_cidrs(self.ex_gw_port['fixed_ips'])
        for old_gateway_cidr in ip_cidrs:
            self._remove_vip(old_gateway_cidr)
        self._add_gateway_vip(ex_gw_port, interface_name)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        self._clear_vips(interface_name)

        if self.ha_state == 'master':
            super(HaRouter, self).external_gateway_removed(ex_gw_port,
                                                           interface_name)
        else:
            # We are not the master node, so no need to delete ip addresses.
            self.driver.unplug(interface_name,
                               namespace=self.ns_name,
                               prefix=router.EXTERNAL_DEV_PREFIX)

    def delete(self):
        if self.process_monitor:
            self.destroy_state_change_monitor(self.process_monitor)
        self.disable_keepalived()
        self.ha_network_removed()
        super(HaRouter, self).delete()

    def process(self):
        super(HaRouter, self).process()

        self.ha_port = self.router.get(n_consts.HA_INTERFACE_KEY)
        if (self.ha_port and
                self.ha_port['status'] == n_consts.PORT_STATUS_ACTIVE):
            self.enable_keepalived()

    @runtime.synchronized('enable_radvd')
    def enable_radvd(self, internal_ports=None):
        if (self.keepalived_manager.get_process().active and
                self.ha_state == 'master'):
            super(HaRouter, self).enable_radvd(internal_ports)
