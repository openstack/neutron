# Copyright (c) 2017 Fujitsu Limited.
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

from neutron_lib.api.definitions import portbindings
from oslo_log import log as logging

from neutron.services.logapi.drivers import base

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_LOGGING_TYPES = ['security_group']


class OVSDriver(base.DriverBase):

    @staticmethod
    def create():
        return OVSDriver(
            name='openvswitch',
            vif_types=[portbindings.VIF_TYPE_OVS,
                       portbindings.VIF_TYPE_VHOST_USER],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_logging_types=SUPPORTED_LOGGING_TYPES,
            requires_rpc=True)


def register():
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = OVSDriver.create()
    LOG.debug('Open vSwitch logging driver registered')
