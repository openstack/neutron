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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from oslo_config import cfg
from oslo_log import log as logging

from neutron.common.ovn import constants as ovn_const


LOG = logging.getLogger(__name__)

# TODO(elvira): Move PVLAN_PLUGIN to neutron_lib.callbacks.resources
PVLAN_PLUGIN = 'pvlan_plugin'


def register(mech_driver):
    def _register_pvlan_driver(resource, event, trigger, payload=None):
        driver = PVLANDriver.create(mech_driver)
        if driver.is_loaded:
            trigger.register_driver(driver)

    registry.subscribe(_register_pvlan_driver,
                       PVLAN_PLUGIN, events.AFTER_INIT)


class PVLANDriver:
    """OVN driver for PVLAN."""

    def __init__(self, mech_driver):
        self._mech_driver = mech_driver

    @classmethod
    def create(cls, mech_driver):
        return cls(mech_driver)

    @property
    def is_loaded(self):
        try:
            return (ovn_const.OVN_ML2_MECH_DRIVER_NAME in
                    cfg.CONF.ml2.mechanism_drivers)
        except cfg.NoSuchOptError:
            return False

    def update_port(self, context, portpvlan,
                    prev_pvlan_type=None, prev_pvlan_community=None):
        """Add or remove LSP related to the Port from port group."""
        pass

    def is_metadata_port(self, port):
        if port.device_id:
            return port.device_id.startswith("ovnmeta")
        return False
