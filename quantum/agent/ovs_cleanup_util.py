# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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

from quantum.agent import l3_agent
from quantum.agent.linux import interface
from quantum.agent.linux import ovs_lib
from quantum.common import config
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """
    opts = [
        cfg.BoolOpt('ovs_all_ports',
                    default=False,
                    help=_('True to delete all ports on all the OpenvSwitch '
                           'bridges. False to delete ports created by '
                           'Quantum on integration and external network '
                           'bridges.'))
    ]

    conf = cfg.CommonConfigOpts()
    conf.register_cli_opts(opts)
    conf.register_opts(l3_agent.L3NATAgent.OPTS)
    conf.register_opts(interface.OPTS)
    config.setup_logging(conf)
    return conf


def main():
    """Main method for cleaning up OVS bridges.

    The utility cleans up the integration bridges used by Quantum.
    """

    conf = setup_conf()
    conf()

    configuration_bridges = set([conf.ovs_integration_bridge,
                                 conf.external_network_bridge])
    ovs_bridges = set(ovs_lib.get_bridges(conf.root_helper))

    if conf.ovs_all_ports:
        bridges = ovs_bridges
    else:
        bridges = configuration_bridges & ovs_bridges

    for bridge in bridges:
        LOG.info(_("Cleaning %s"), bridge)
        ovs = ovs_lib.OVSBridge(bridge, conf.root_helper)
        ovs.delete_ports(all_ports=conf.ovs_all_ports)

    LOG.info(_("OVS cleanup completed successfully"))
