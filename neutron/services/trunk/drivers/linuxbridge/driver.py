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

from oslo_config import cfg
from oslo_log import log as logging

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.services.trunk import constants as trunk_consts

from neutron.services.trunk.drivers import base

LOG = logging.getLogger(__name__)

NAME = 'linuxbridge'
SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_BRIDGE,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)


class LinuxBridgeDriver(base.DriverBase):
    """Server-side Trunk driver for the ML2 Linux Bridge driver."""

    @property
    def is_loaded(self):
        try:
            return NAME in cfg.CONF.ml2.mechanism_drivers
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls):
        return cls(NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES,
                   constants.AGENT_TYPE_LINUXBRIDGE, can_trunk_bound_port=True)


def register():
    # NOTE(kevinbenton): the thing that is keeping this from being
    # immediately garbage collected is that it registers callbacks
    LinuxBridgeDriver.create()
    LOG.debug("Linux bridge trunk driver initialized.")
