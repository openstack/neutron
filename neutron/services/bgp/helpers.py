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

import uuid

from oslo_log import log


LOG = log.getLogger(__name__)

BGP_LRP_UUID_NAMESPACE = uuid.UUID('9eaaac59-33fc-4f45-a450-8c220d46ad95')


def get_mac_address_from_lrp_name(lrp_name):
    mac_uuid_base = uuid.uuid5(BGP_LRP_UUID_NAMESPACE, lrp_name)

    # Let's take last 6 bytes of the UUID and convert them to bytes
    mac_bytes = bytearray(mac_uuid_base.bytes[-6:])

    # 3. Apply Bitwise Operations on the First Byte
    # Set the "Locally Administered" bit (2nd least significant bit) to 1
    # xxxxxxx1 | 00000010 = xxxxxxx1 (OR 0x02)
    mac_bytes[0] |= 0x02

    # Clear the "Multicast" bit (Least significant bit) to 0
    # xxxxxxx1 & 11111110 = xxxxxxx0 (AND 0xfe)
    mac_bytes[0] &= 0xfe

    # 4. Format into standard MAC string (XX:XX:XX:XX:XX:XX)
    mac_address = ':'.join(f'{b:02x}' for b in mac_bytes)

    return mac_address


# Naming helper functions
def get_lrp_name(from_name, to_name):
    return f'bgp-lrp-{from_name}-to-{to_name}'


def get_hcg_name(chassis_name):
    return f'bgp-hcg-{chassis_name}'


def get_chassis_router_name(chassis_name):
    return f'bgp-lr-{chassis_name}'
