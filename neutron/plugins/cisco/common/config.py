# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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

from oslo.config import cfg

from neutron.agent.common import config


cisco_plugins_opts = [
    cfg.StrOpt('vswitch_plugin',
               default='neutron.plugins.openvswitch.ovs_neutron_plugin.'
                       'OVSNeutronPluginV2',
               help=_("Virtual Switch to use")),
    cfg.StrOpt('nexus_plugin',
               default='neutron.plugins.cisco.nexus.cisco_nexus_plugin_v2.'
                       'NexusPlugin',
               help=_("Nexus Switch to use")),
]


cisco_opts = [
    cfg.StrOpt('vlan_start', default='100',
               help=_("VLAN start value")),
    cfg.StrOpt('vlan_end', default='3000',
               help=_("VLAN end value")),
    cfg.StrOpt('vlan_name_prefix', default='q-',
               help=_("VLAN Name prefix")),
    cfg.StrOpt('max_ports', default='100',
               help=_("Maximum Port value")),
    cfg.StrOpt('max_port_profiles', default='65568',
               help=_("Maximum Port Profile value")),
    cfg.StrOpt('max_networks', default='65568',
               help=_("Maximum Network value")),
    cfg.BoolOpt('svi_round_robin', default=False,
                help=_("Distribute SVI interfaces over all switches")),
    cfg.StrOpt('model_class',
               default='neutron.plugins.cisco.models.virt_phy_sw_v2.'
                       'VirtualPhysicalSwitchModelV2',
               help=_("Model Class")),
    cfg.StrOpt('manager_class',
               default='neutron.plugins.cisco.segmentation.'
                       'l2network_vlan_mgr_v2.L2NetworkVLANMgr',
               help=_("Manager Class")),
    cfg.StrOpt('nexus_driver',
               default='neutron.plugins.cisco.test.nexus.'
                       'fake_nexus_driver.CiscoNEXUSFakeDriver',
               help=_("Nexus Driver Name")),
]

cfg.CONF.register_opts(cisco_opts, "CISCO")
cfg.CONF.register_opts(cisco_plugins_opts, "CISCO_PLUGINS")
config.register_root_helper(cfg.CONF)

# shortcuts
CONF = cfg.CONF
CISCO = cfg.CONF.CISCO
CISCO_PLUGINS = cfg.CONF.CISCO_PLUGINS

#
# When populated the nexus_dictionary format is:
# {('<nexus ipaddr>', '<key>'): '<value>', ...}
#
# Example:
# {('1.1.1.1', 'username'): 'admin',
#  ('1.1.1.1', 'password'): 'mySecretPassword',
#  ('1.1.1.1', 'ssh_port'): 22,
#  ('1.1.1.1', 'compute1'): '1/1', ...}
#
nexus_dictionary = {}


class CiscoConfigOptions():
    """Cisco Configuration Options Class."""

    def __init__(self):
        self._create_nexus_dictionary()

    def _create_nexus_dictionary(self):
        """Create the Nexus dictionary.

        Reads data from cisco_plugins.ini NEXUS_SWITCH section(s).
        """

        multi_parser = cfg.MultiConfigParser()
        read_ok = multi_parser.read(CONF.config_file)

        if len(read_ok) != len(CONF.config_file):
            raise cfg.Error("Some config files were not parsed properly")

        for parsed_file in multi_parser.parsed:
            for parsed_item in parsed_file.keys():
                nexus_name, sep, nexus_ip = parsed_item.partition(':')
                if nexus_name.lower() == "nexus_switch":
                    for nexus_key, value in parsed_file[parsed_item].items():
                        nexus_dictionary[nexus_ip, nexus_key] = value[0]


def get_nexus_dictionary():
    return nexus_dictionary
