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

from neutron._i18n import _LI
from neutron.agent.common import config as agent_config
from neutron.agent.common import ovs_lib
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import config
from neutron.conf.agent import cmd
from neutron.conf.agent.l3 import config as l3_config


LOG = logging.getLogger(__name__)


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """

    conf = cfg.CONF
    cmd.register_cmd_opts(cmd.ovs_opts, conf)
    l3_config.register_l3_agent_config_opts(l3_config.OPTS, conf)
    conf.register_opts(interface.OPTS)
    agent_config.register_interface_driver_opts_helper(conf)
    return conf


def collect_neutron_ports(bridges):
    """Collect ports created by Neutron from OVS."""
    ports = []
    for bridge in bridges:
        ovs = ovs_lib.OVSBridge(bridge)
        ports += [port.port_name for port in ovs.get_vif_ports()]
    return ports


def delete_neutron_ports(ports):
    """Delete non-internal ports created by Neutron

    Non-internal OVS ports need to be removed manually.
    """
    for port in ports:
        device = ip_lib.IPDevice(port)
        if device.exists():
            device.link.delete()
            LOG.info(_LI("Deleting port: %s"), port)


def main():
    """Main method for cleaning up OVS bridges.

    The utility cleans up the integration bridges used by Neutron.
    """

    conf = setup_conf()
    conf()
    config.setup_logging()
    do_main(conf)


def do_main(conf):
    configuration_bridges = set([conf.ovs_integration_bridge,
                                 conf.external_network_bridge])
    ovs = ovs_lib.BaseOVS()
    ovs_bridges = set(ovs.get_bridges())
    available_configuration_bridges = configuration_bridges & ovs_bridges

    if conf.ovs_all_ports:
        bridges = ovs_bridges
    else:
        bridges = available_configuration_bridges

    try:
        # The ovs_cleanup method not added to the deprecated vsctl backend
        for bridge in bridges:
            LOG.info(_LI("Cleaning bridge: %s"), bridge)
            ovs.ovsdb.ovs_cleanup(bridge,
                                  conf.ovs_all_ports).execute(check_error=True)
    except AttributeError:

        # Collect existing ports created by Neutron on configuration bridges.
        # After deleting ports from OVS bridges, we cannot determine which
        # ports were created by Neutron, so port information is collected now.
        ports = collect_neutron_ports(available_configuration_bridges)

        for bridge in bridges:
            LOG.info(_LI("Cleaning bridge: %s"), bridge)
            ovs = ovs_lib.OVSBridge(bridge)
            ovs.delete_ports(all_ports=conf.ovs_all_ports)

        # Remove remaining ports created by Neutron (usually veth pair)
        delete_neutron_ports(ports)

    LOG.info(_LI("OVS cleanup completed successfully"))
