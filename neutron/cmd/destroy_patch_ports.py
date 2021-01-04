# Copyright 2020 Red Hat, Inc.
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

import sys

from neutron_lib.plugins import utils as p_utils
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import ovs_lib
from neutron.common import config as common_config
from neutron.conf.agent import common as agent_config
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants

LOG = logging.getLogger(__name__)


def get_patch_port_names(bridge_name):
    int_if_name = p_utils.get_interface_name(
        bridge_name, prefix=constants.PEER_INTEGRATION_PREFIX)
    phys_if_name = p_utils.get_interface_name(
        bridge_name, prefix=constants.PEER_PHYSICAL_PREFIX)

    return int_if_name, phys_if_name


class PatchPortCleaner(object):
    def __init__(self, config):
        LOG.debug("Get OVS bridge mappings")
        mappings = helpers.parse_mappings(config.OVS.bridge_mappings)
        self.bridges = [ovs_lib.OVSBridge(bridge)
                        for bridge in mappings.values()]
        self.int_br = ovs_lib.OVSBridge(config.OVS.integration_bridge)

    def destroy_patch_ports(self):
        if (not self.int_br.bridge_exists(self.int_br.br_name) or
                self.flows_configured()):
            # integration bridge hasn't been created by agent yet or it's been
            # already configured by the agent
            return
        for bridge in self.bridges:
            try:
                LOG.debug("Remove patch port from bridge %s", bridge.br_name)
                self._remove_patch_ports_from_int_br(bridge)
            except Exception as e:
                LOG.error("Failed to remove patch port from bridge %s: %s",
                          bridge.br_name, e)

    def _remove_patch_ports_from_int_br(self, bridge):
        int_if_name, phys_if_name = get_patch_port_names(
            bridge.br_name)
        int_type = self.int_br.db_get_val(
            "Interface", int_if_name, "type", log_errors=False)
        if int_type == 'patch':
            self.int_br.delete_port(int_if_name)
            bridge.delete_port(phys_if_name)

    def flows_configured(self):
        """Return True if the integration bridge has flows already configured.
        """
        LOG.debug("Get configured flows for integration bridge %s",
                  self.int_br.br_name)
        return bool(self.int_br.dump_flows_for(table=constants.CANARY_TABLE))


def main():
    common_config.init(sys.argv[1:])
    ovs_conf.register_ovs_agent_opts()
    common_config.setup_logging()
    agent_config.setup_privsep()
    port_cleaner = PatchPortCleaner(cfg.CONF)
    port_cleaner.destroy_patch_ports()


if __name__ == "__main__":
    main()
