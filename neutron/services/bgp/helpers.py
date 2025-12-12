# Copyright 2025 Red Hat, Inc.
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

import netaddr
from oslo_log import log

from neutron.services.bgp import constants
from neutron.services.bgp import exceptions

LOG = log.getLogger(__name__)


class _BgpRouterMacPrefix:
    MAC_BYTES = 6

    def __init__(self, mac_prefix):
        mac_prefix_len = len([byte for byte in mac_prefix.split(':') if byte])
        if mac_prefix_len >= self.MAC_BYTES:
            raise ValueError(f"MAC prefix {mac_prefix} is too long")
        remaining_bytes = self.MAC_BYTES - mac_prefix_len
        self.mac_prefix = mac_prefix
        self.max_mac_index = self.calculate_max_mac_generated(remaining_bytes)
        self.remaining_bytes = remaining_bytes

    @staticmethod
    def calculate_max_mac_generated(remaining_bytes):
        """Calculate how many MAC address can be generated

        This means depending on how many bytes are left after the MAC prefix,
        we can generate 255^n MAC addresses, where n is the number of bytes
        left.

        For example if a mac prefix is 00:00 - it uses 2 bytes, and MAC address
        is stored in 6 bytes. That gives us 4 bytes left and hence
        255^4 MAC addresses.
        """
        return 255 ** remaining_bytes - 1


class LrpMacManager:
    def __init__(self):
        self.known_routers = {}

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = cls()
        return cls._instance

    def register_router(self, router_name, mac_prefix):
        LOG.debug("Registering router %s with mac prefix %s",
                  router_name, mac_prefix)
        self.known_routers[router_name] = _BgpRouterMacPrefix(mac_prefix)

    def get_mac_address(self, router_name, index):
        try:
            router = self.known_routers[router_name]
        except KeyError:
            raise RuntimeError(f"Router {router_name} not registered")

        if index < 0 or index > router.max_mac_index:
            raise ValueError(
                f"Index {index} is out of range, maximum is "
                f"{router.max_mac_index}")

        # generates the hex string based on the remaining bytes
        # example: if remaining bytes is 3, and index is 100 will be 000064
        # because 100 in dec is 64 in hex + 4 zeros to make it 3 bytes
        hex_str = f"{index:0{router.remaining_bytes * 2}x}"

        # inserts colons between the hex bytes
        # example: 000064 will be 00:00:64
        hex_bytes = ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

        # combines the mac prefix and the hex bytes into a valid mac address
        # example: {00:00:00}:{00:00:64} is prefix + hex bytes
        result = f'{router.mac_prefix}:{hex_bytes}'

        try:
            netaddr.EUI(result, version=48)
        except netaddr.core.AddrFormatError:
            raise ValueError(f"Invalid generated MAC address: {result}")

        return result


def get_all_chassis(sb_ovn):
    chassis = sb_ovn.db_find_rows('Chassis').execute(check_error=True)
    return chassis


# Naming helper functions
def get_lrp_name(from_name, to_name):
    return f'bgp-lrp-{from_name}-to-{to_name}'


def get_hcg_name(chassis_name):
    return f'bgp-hcg-{chassis_name}'


def get_chassis_router_name(chassis_name):
    return f'bgp-lr-{chassis_name}'


def get_chassis_index(chassis):
    try:
        return int(chassis.external_ids[constants.OVN_BGP_CHASSIS_INDEX_KEY])
    except (KeyError, ValueError):
        msg = (f"Chassis {chassis.name} has no index required for further "
               "operations, such as creating chassis BGP resources")
        LOG.error(msg)
        # TODO(jlibosva): Use resource types for custom exceptions
        raise exceptions.ReconcileError(msg)
