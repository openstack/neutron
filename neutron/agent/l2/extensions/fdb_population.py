# Copyright (c) 2016 Mellanox Technologies, Ltd
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

import sys

from neutron_lib.agent import l2_extension
from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from pyroute2.netlink import exceptions as netlink_exceptions

from neutron.agent.linux import bridge_lib
from neutron.conf.agent import l2_ext_fdb_population

l2_ext_fdb_population.register_fdb_population_opts()

LOG = logging.getLogger(__name__)


class FdbPopulationAgentExtension(
        l2_extension.L2AgentExtension):
    """The FDB population is an agent extension to OVS
    whose objective is to update the FDB table for existing instance
    using normal port, thus enabling communication between SR-IOV instances
    and normal instances.
    Additional information describing the problem can be found here:
    http://events.linuxfoundation.org/sites/events/files/slides/LinuxConJapan2014_makita_0.pdf
    """

    # FDB updates are triggered for ports with a certain device_owner only:
    # - device owner "compute": updates the FDB with normal port instances,
    #       required in order to enable communication between
    #       SR-IOV direct port instances and normal port instance.
    # - device owner "router_interface": updates the FDB with OVS/LB ports,
    #       required in order to enable communication for SR-IOV instances
    #       with floating ip that are located with the network node.
    # - device owner "DHCP": updates the FDB with the dhcp server.
    #       When the lease expires a unicast renew message is sent
    #       to the dhcp server. In case the FDB is not updated
    #       the message will be sent to the wire, causing the message
    #       to get lost in case the sender uses direct port and is
    #       located on the same hypervisor as the network node.
    PERMITTED_DEVICE_OWNERS = {constants.DEVICE_OWNER_COMPUTE_PREFIX,
                               constants.DEVICE_OWNER_ROUTER_INTF,
                               constants.DEVICE_OWNER_DHCP}

    class FdbTableTracker:
        """FDB table tracker is a helper class
        intended to keep track of the existing FDB rules.
        """
        def __init__(self, devices):
            self.device_to_macs = {}
            self.portid_to_mac = {}
            # update macs already in the physical interface's FDB table
            for device in devices:
                try:
                    rules = bridge_lib.FdbInterface.show(dev=device)
                except (OSError, netlink_exceptions.NetlinkError) as e:
                    LOG.warning(
                        'Unable to find FDB Interface %(device)s. '
                        'Exception: %(e)s', {'device': device, 'e': e})
                    continue
                self.device_to_macs[device] = [rule['mac'] for rule in
                                               rules[device]]

        def update_port(self, device, port_id, mac):
            # check if device is updated
            if self.device_to_macs.get(device) == mac:
                return
            # delete invalid port_id's mac from the FDB,
            # in case the port was updated to another mac
            self.delete_port([device], port_id)
            # update port id
            self.portid_to_mac[port_id] = mac
            # check if rule for mac already exists
            if mac in self.device_to_macs[device]:
                return
            if not bridge_lib.FdbInterface.add(mac, device):
                LOG.warning('Unable to add mac %(mac)s to FDB Interface '
                            '%(device)s.', {'mac': mac, 'device': device})
                return
            self.device_to_macs[device].append(mac)

        def delete_port(self, devices, port_id):
            mac = self.portid_to_mac.get(port_id)
            if mac is None:
                LOG.warning('Port Id %(port_id)s does not have a rule for '
                            'devices %(devices)s in FDB table',
                            {'port_id': port_id, 'devices': devices})
                return
            for device in devices:
                if mac in self.device_to_macs[device]:
                    if not bridge_lib.FdbInterface.delete(mac, device):
                        LOG.warning('Unable to delete mac %(mac)s from FDB '
                                    'Interface %(device)s.',
                                    {'mac': mac, 'device': device})
                        return
                    self.device_to_macs[device].remove(mac)
                    del self.portid_to_mac[port_id]

    # class FdbPopulationAgentExtension implementation:
    def initialize(self, connection, driver_type):
        """Perform FDB Agent Extension initialization."""
        if driver_type != ovs_constants.EXTENSION_DRIVER_TYPE:
            LOG.error('FDB extension is only supported for OVS agent, '
                      f'currently uses {driver_type}')
            sys.exit(1)

        self.device_mappings = helpers.parse_mappings(
            cfg.CONF.FDB.shared_physical_device_mappings, unique_keys=False)
        devices = self._get_devices()
        if not devices:
            LOG.error('Invalid configuration provided for FDB extension: '
                      'no physical devices')
            sys.exit(1)
        self.fdb_tracker = self.FdbTableTracker(devices)

    def handle_port(self, context, details):
        """Handle agent FDB population extension for port."""
        device_owner = details['device_owner']
        if self._is_valid_device_owner(device_owner):
            mac = details['mac_address']
            port_id = details['port_id']
            physnet = details.get('physical_network')
            if physnet and physnet in self.device_mappings:
                for device in self.device_mappings[physnet]:
                    self.fdb_tracker.update_port(device, port_id, mac)

    def delete_port(self, context, details):
        """Delete port from FDB population extension."""
        port_id = details['port_id']
        devices = self._get_devices()
        self.fdb_tracker.delete_port(devices, port_id)

    def _get_devices(self):
        def _flatten_list(li):
            return [item for sublist in li for item in sublist]

        return _flatten_list(self.device_mappings.values())

    def _is_valid_device_owner(self, device_owner):
        for permitted_device_owner in self.PERMITTED_DEVICE_OWNERS:
            if device_owner.startswith(permitted_device_owner):
                return True
        return False
