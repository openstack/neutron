# Copyright 2012 Cisco Systems, Inc.
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
#

from neutron_lib import constants as n_const
from oslo_log import log

from neutron.plugins.ml2.drivers.linuxbridge.agent.common import constants

LOG = log.getLogger(__name__)


def get_tap_device_name(interface_id):
    """Convert port ID into device name format expected by linux bridge."""
    if not interface_id:
        LOG.warning("Invalid Interface ID, will lead to incorrect "
                    "tap device name")
    tap_device_name = (n_const.TAP_DEVICE_PREFIX +
                       interface_id[:constants.RESOURCE_ID_LENGTH])
    return tap_device_name
