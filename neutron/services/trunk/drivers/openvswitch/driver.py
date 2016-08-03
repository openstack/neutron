# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging

from neutron.extensions import portbindings
from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base

LOG = logging.getLogger(__name__)

NAME = 'openvswitch'

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.VLAN,
)

DRIVER = None


class OVSDriver(base.DriverBase):

    @property
    def is_loaded(self):
        return NAME in cfg.CONF.ml2.mechanism_drivers

    @classmethod
    def create(cls):
        return OVSDriver(NAME,
                         SUPPORTED_INTERFACES,
                         SUPPORTED_SEGMENTATION_TYPES,
                         constants.AGENT_TYPE_OVS)


def register():
    """Register the driver."""
    global DRIVER
    DRIVER = OVSDriver.create()
    LOG.debug('Open vSwitch trunk driver registered')
