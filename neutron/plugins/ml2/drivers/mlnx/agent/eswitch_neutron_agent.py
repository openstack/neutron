# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys

from networking_mlnx.plugins.ml2.drivers.mlnx.agent import (
    mlnx_eswitch_neutron_agent)
from oslo_config import cfg
from oslo_log import log as logging

from neutron.i18n import _LE, _LI
from neutron.common import config as common_config
from neutron.common import utils
from neutron.plugins.ml2.drivers.mlnx.agent import config  # noqa

LOG = logging.getLogger(__name__)


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    try:
        interface_mappings = utils.parse_mappings(
            cfg.CONF.ESWITCH.physical_interface_mappings)
    except ValueError as e:
        LOG.error(_LE("Parsing physical_interface_mappings failed: %s. "
                      "Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_LI("Interface mappings: %s"), interface_mappings)

    try:
        agent = mlnx_eswitch_neutron_agent.MlnxEswitchNeutronAgent(
            interface_mappings)
    except Exception as e:
        LOG.error(_LE("Failed on Agent initialisation : %s. "
                      "Agent terminated!"), e)
        sys.exit(1)

    # Start everything.
    LOG.info(_LI("Agent initialised successfully, now running... "))
    agent.run()
    sys.exit(0)


if __name__ == '__main__':
    main()
