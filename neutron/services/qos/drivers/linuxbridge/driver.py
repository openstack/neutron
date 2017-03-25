# Copyright (c) 2016 Red Hat Inc.
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

from oslo_log import log as logging

from neutron.extensions import portbindings
from neutron.services.qos.drivers import base
from neutron.services.qos import qos_consts

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_RULES = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                   qos_consts.RULE_TYPE_DSCP_MARKING]


class LinuxBridgeDriver(base.DriverBase):

    @staticmethod
    def create():
        return LinuxBridgeDriver(
            name='linuxbridge',
            vif_types=[portbindings.VIF_TYPE_BRIDGE],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_rules=SUPPORTED_RULES,
            requires_rpc_notifications=True)


def register():
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = LinuxBridgeDriver.create()
    LOG.debug('Linuxbridge QoS driver registered')
