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

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib.services.trunk import constants as trunk_consts
from oslo_config import cfg
from oslo_log import log as logging

from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
    constants as agent_consts)
from neutron.services.trunk.drivers import base
from neutron.services.trunk.drivers.openvswitch import utils

LOG = logging.getLogger(__name__)

NAME = 'openvswitch'

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
    portbindings.VIF_TYPE_VHOST_USER,
)

SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)

DRIVER = None


class OVSDriver(base.DriverBase):

    @property
    def is_loaded(self):
        try:
            return NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

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
    # To set the bridge_name in a parent port's vif_details.
    registry.subscribe(vif_details_bridge_name_handler,
                       agent_consts.OVS_BRIDGE_NAME,
                       events.BEFORE_READ)
    LOG.debug('Open vSwitch trunk driver registered')


def vif_details_bridge_name_handler(resource, event, set_br_name,
                                    payload=None):
    """If port is a trunk port, generate a bridge_name for its vif_details."""
    port = payload.metadata['port']
    if 'trunk_details' in port:
        set_br_name(utils.gen_trunk_br_name(port['trunk_details']['trunk_id']))
