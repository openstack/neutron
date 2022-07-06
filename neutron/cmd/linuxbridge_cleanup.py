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

import sys

from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import config as common_config
from neutron.conf.agent import common as config
from neutron.plugins.ml2.drivers.linuxbridge.agent \
    import linuxbridge_neutron_agent


LOG = logging.getLogger(__name__)


def remove_empty_bridges():
    try:
        interface_mappings = helpers.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.physical_interface_mappings)
    except ValueError as e:
        LOG.error("Parsing physical_interface_mappings failed: %s.", e)
        sys.exit(1)
    LOG.info("Interface mappings: %s.", interface_mappings)

    try:
        bridge_mappings = helpers.parse_mappings(
            cfg.CONF.LINUX_BRIDGE.bridge_mappings)
    except ValueError as e:
        LOG.error("Parsing bridge_mappings failed: %s.", e)
        sys.exit(1)
    LOG.info("Bridge mappings: %s.", bridge_mappings)

    lb_manager = linuxbridge_neutron_agent.LinuxBridgeManager(
        bridge_mappings, interface_mappings)

    bridge_names = lb_manager.get_deletable_bridges()
    for bridge_name in bridge_names:
        if lb_manager.get_tap_devices_count(bridge_name):
            continue

        try:
            lb_manager.delete_bridge(bridge_name)
            LOG.info("Linux bridge %s deleted", bridge_name)
        except RuntimeError:
            LOG.exception("Linux bridge %s delete failed", bridge_name)
    LOG.info("Linux bridge cleanup completed successfully")


def main():
    """Main method for cleaning up empty linux bridges.

    This tool deletes every empty linux bridge managed by linuxbridge agent
    (brq.* linux bridges) except these ones defined using bridge_mappings
    option in section LINUX_BRIDGE (created by deployers).

    This tool should not be called during an instance create, migrate, etc. as
    it can delete a linux bridge about to be used by nova.
    """
    common_config.register_common_config_options()
    cfg.CONF(sys.argv[1:])
    config.setup_logging()
    config.setup_privsep()
    remove_empty_bridges()
