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

from neutron_lib import constants as n_const
from neutron_lib.plugins import utils as plugin_utils


MAX_VLAN_POSTFIX_LEN = 5


def get_vlan_device_name(src_dev, vlan):
    """Generating the vlan device name."""

    # Ensure that independent of the vlan len the same name prefix is used.
    src_dev = plugin_utils.get_interface_name(
        src_dev, max_len=n_const.DEVICE_NAME_MAX_LEN - MAX_VLAN_POSTFIX_LEN)
    return f"{src_dev}.{vlan}"
