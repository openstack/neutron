# Copyright (c) 2016 IBM Corp.
#
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
import sys

from neutron_lib.agent import topics
from neutron_lib import constants
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import service

from neutron.agent.linux import ip_lib
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.conf.plugins.ml2.drivers import macvtap as config
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import _common_agent as ca
from neutron.plugins.ml2.drivers.macvtap import macvtap_common

LOG = logging.getLogger(__name__)

MACVTAP_AGENT_BINARY = "neutron-macvtap-agent"
MACVTAP_FS = "/sys/class/net/"
EXTENSION_DRIVER_TYPE = 'macvtap'

config.register_macvtap_opts()


class MacvtapRPCCallBack(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                         amb.CommonAgentManagerRpcCallBackBase):
    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    #   1.3 Added param devices_to_update to security_groups_provider_updated
    #   1.4 Added support for network_update
    target = oslo_messaging.Target(version='1.4')

    def network_delete(self, context, **kwargs):
        LOG.debug("network_delete received")
        network_id = kwargs.get('network_id')

        if network_id not in self.network_map:
            LOG.error("Network %s is not available.", network_id)
            return

        segment = self.network_map.get(network_id)
        if segment and segment.network_type == constants.TYPE_VLAN:
            if_mappings = self.agent.mgr.interface_mappings
            vlan_device_name = macvtap_common.get_vlan_device_name(
                if_mappings[segment.physical_network],
                str(segment.segmentation_id))
            ip_dev = ip_lib.IPDevice(vlan_device_name)
            if ip_dev.exists():
                LOG.debug("Delete %s", ip_dev.name)
                ip_dev.link.delete()
            else:
                LOG.debug("Cannot delete vlan device %s; it does not exist",
                          vlan_device_name)

    def port_update(self, context, **kwargs):
        port = kwargs['port']
        LOG.debug("port_update received for port %s ", port)
        mac = port['mac_address']
        # Put the device name in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.updated_devices.add(mac)


class MacvtapManager(amb.CommonAgentManagerBase):
    def __init__(self, interface_mappings):
        self.interface_mappings = interface_mappings
        self.validate_interface_mappings()
        self.mac_device_name_mappings = dict()

    def validate_interface_mappings(self):
        for physnet, interface in self.interface_mappings.items():
            if not ip_lib.device_exists(interface):
                LOG.error("Interface %(intf)s for physical network "
                          "%(net)s does not exist. Agent terminated!",
                          {'intf': interface, 'net': physnet})
                sys.exit(1)

    def ensure_port_admin_state(self, device, admin_state_up):
        LOG.debug("Setting admin_state_up to %s for device %s",
                  admin_state_up, device)
        dev = ip_lib.IPDevice(self.mac_device_name_mappings[device])
        if admin_state_up:
            dev.link.set_up()
        else:
            dev.link.set_down()

    def get_agent_configurations(self):
        return {'interface_mappings': self.interface_mappings}

    def get_agent_id(self):
        devices = ip_lib.IPWrapper().get_devices(True)
        for device in devices:
            mac = ip_lib.get_device_mac(device.name)
            if mac:
                return 'macvtap%s' % mac.replace(":", "")
        LOG.error("Unable to obtain MAC address for unique ID. "
                  "Agent terminated!")
        sys.exit(1)

    def get_devices_modified_timestamps(self, devices):
        # TODO(kevinbenton): this should be implemented to detect
        # rapid Nova instance rebuilds.
        return {}

    def get_all_devices(self):
        devices = set()
        all_device_names = os.listdir(MACVTAP_FS)
        # Refresh the mac_device_name mapping
        self.mac_device_name_mappings = dict()
        for device_name in all_device_names:
            if device_name.startswith(constants.MACVTAP_DEVICE_PREFIX):
                mac = ip_lib.get_device_mac(device_name)
                self.mac_device_name_mappings[mac] = device_name
                devices.add(mac)
        return devices

    def get_extension_driver_type(self):
        return EXTENSION_DRIVER_TYPE

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return MacvtapRPCCallBack(context, agent, sg_agent)

    def get_agent_api(self, **kwargs):
        pass

    def get_rpc_consumers(self):
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        return consumers

    def plug_interface(self, network_id, network_segment, device,
                       device_owner):
        # Setting ALLMULTICAST Flag on macvtap device to allow the guest
        # receiving traffic for arbitrary multicast addresses.
        # The alternative would be to let libvirt instantiate the macvtap
        # device with the 'trustGuestRxFilters' option. But doing so, the guest
        # would be able to change its mac address and therefore the mac
        # address of the macvtap device.
        dev = ip_lib.IPDevice(self.mac_device_name_mappings[device])
        dev.link.set_allmulticast_on()
        return True

    def setup_arp_spoofing_protection(self, device, device_details):
        pass

    def delete_arp_spoofing_protection(self, devices):
        pass

    def delete_unreferenced_arp_protection(self, current_devices):
        pass


def parse_interface_mappings():
    if not cfg.CONF.macvtap.physical_interface_mappings:
        LOG.error("No physical_interface_mappings provided, but at least "
                  "one mapping is required. Agent terminated!")
        sys.exit(1)

    try:
        interface_mappings = helpers.parse_mappings(
            cfg.CONF.macvtap.physical_interface_mappings)
        LOG.info("Interface mappings: %s", interface_mappings)
        return interface_mappings
    except ValueError as e:
        LOG.error("Parsing physical_interface_mappings failed: %s. "
                  "Agent terminated!", e)
        sys.exit(1)


def validate_firewall_driver():
    fw_driver = cfg.CONF.SECURITYGROUP.firewall_driver
    supported_fw_drivers = ['neutron.agent.firewall.NoopFirewallDriver',
                            'noop']
    if fw_driver not in supported_fw_drivers:
        LOG.error('Unsupported configuration option for "SECURITYGROUP.'
                  'firewall_driver"! Only the NoopFirewallDriver is '
                  'supported by macvtap agent, but "%s" is configured. '
                  'Set the firewall_driver to "noop" and start the '
                  'agent again. Agent terminated!',
                  fw_driver)
        sys.exit(1)


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()

    validate_firewall_driver()
    interface_mappings = parse_interface_mappings()

    manager = MacvtapManager(interface_mappings)

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = ca.CommonAgentLoop(manager, polling_interval,
                               quitting_rpc_timeout,
                               constants.AGENT_TYPE_MACVTAP,
                               MACVTAP_AGENT_BINARY)
    LOG.info("Agent initialized successfully, now running... ")
    launcher = service.launch(cfg.CONF, agent, restart_method='mutate')
    launcher.wait()
