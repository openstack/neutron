# Copyright (c) 2012 OpenStack Foundation.
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import ovs_lib
from neutron.common import config
from neutron.conf.agent import cmd
from neutron.conf.agent import common as agent_config
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.plugins.ml2.drivers import ovs_conf
from neutron.conf import service as service_config

LOG = logging.getLogger(__name__)

# Default ovsdb_timeout value for this script.
# It allows to clean bridges with even thousands of ports.
CLEANUP_OVSDB_TIMEOUT = 600


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """

    conf = cfg.CONF
    config.register_common_config_options()
    cmd.register_cmd_opts(cmd.ovs_opts, conf)
    l3_config.register_l3_agent_config_opts(l3_config.OPTS, conf)
    agent_config.register_interface_driver_opts_helper(conf)
    agent_config.register_interface_opts()
    service_config.register_service_opts(service_config.RPC_EXTRA_OPTS, conf)
    ovs_conf.register_ovs_agent_opts(conf)
    conf.set_default("ovsdb_timeout", CLEANUP_OVSDB_TIMEOUT, "OVS")
    return conf


def main():
    """Main method for cleaning up OVS bridges.

    The utility cleans up the integration bridges used by Neutron.
    """

    conf = setup_conf()
    conf()
    config.setup_logging()
    agent_config.setup_privsep()
    do_main(conf)


def do_main(conf):
    configuration_bridges = set([conf.OVS.integration_bridge])
    ovs = ovs_lib.BaseOVS()
    ovs_bridges = set(ovs.get_bridges())
    available_configuration_bridges = configuration_bridges & ovs_bridges

    if conf.ovs_all_ports:
        bridges = ovs_bridges
    else:
        bridges = available_configuration_bridges

    for bridge in bridges:
        LOG.info("Cleaning bridge: %s", bridge)
        ovs.ovsdb.ovs_cleanup(bridge,
                              conf.ovs_all_ports).execute(check_error=True)

    LOG.info("OVS cleanup completed successfully")
