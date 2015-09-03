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

from oslo_config import cfg


cisco_opts = [
    cfg.StrOpt('vlan_name_prefix', default='q-',
               help=_("VLAN Name prefix")),
    cfg.StrOpt('provider_vlan_name_prefix', default='p-',
               help=_("VLAN Name prefix for provider vlans")),
    cfg.BoolOpt('provider_vlan_auto_create', default=True,
                help=_('Provider VLANs are automatically created as needed '
                       'on the Nexus switch')),
    cfg.BoolOpt('provider_vlan_auto_trunk', default=True,
                help=_('Provider VLANs are automatically trunked as needed '
                       'on the ports of the Nexus switch')),
    cfg.BoolOpt('nexus_l3_enable', default=False,
                help=_("Enable L3 support on the Nexus switches")),
    cfg.BoolOpt('svi_round_robin', default=False,
                help=_("Distribute SVI interfaces over all switches")),
    cfg.StrOpt('model_class',
               default='neutron.plugins.cisco.models.virt_phy_sw_v2.'
                       'VirtualPhysicalSwitchModelV2',
               help=_("Model Class")),
]

cisco_n1k_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("N1K Integration Bridge")),
    cfg.BoolOpt('enable_tunneling', default=True,
                help=_("N1K Enable Tunneling")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("N1K Tunnel Bridge")),
    cfg.StrOpt('local_ip', default='10.0.0.3',
               help=_("N1K Local IP")),
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("N1K Tenant Network Type")),
    cfg.StrOpt('bridge_mappings', default='',
               help=_("N1K Bridge Mappings")),
    cfg.StrOpt('vxlan_id_ranges', default='5000:10000',
               help=_("N1K VXLAN ID Ranges")),
    cfg.StrOpt('network_vlan_ranges', default='vlan:1:4095',
               help=_("N1K Network VLAN Ranges")),
    cfg.StrOpt('default_network_profile', default='default_network_profile',
               help=_("N1K default network profile")),
    cfg.StrOpt('default_policy_profile', default='service_profile',
               help=_("N1K default policy profile")),
    cfg.StrOpt('network_node_policy_profile', default='dhcp_pp',
               help=_("N1K policy profile for network node")),
    cfg.IntOpt('poll_duration', default=60,
               help=_("N1K Policy profile polling duration in seconds")),
    cfg.BoolOpt('restrict_policy_profiles', default=False,
               help=_("Restrict the visibility of policy profiles to the "
                      "tenants")),
    cfg.IntOpt('http_pool_size', default=4,
               help=_("Number of threads to use to make HTTP requests")),
    cfg.IntOpt('http_timeout', default=15,
               help=_("N1K http timeout duration in seconds")),
    cfg.BoolOpt('restrict_network_profiles', default=True,
               help=_("Restrict tenants from accessing network profiles "
                      "belonging to some other tenant")),

]

cfg.CONF.register_opts(cisco_opts, "CISCO")
cfg.CONF.register_opts(cisco_n1k_opts, "CISCO_N1K")

# shortcuts
CONF = cfg.CONF
CISCO = cfg.CONF.CISCO
CISCO_N1K = cfg.CONF.CISCO_N1K

#
# device_dictionary - Contains all external device configuration.
#
# When populated the device dictionary format is:
# {('<device ID>', '<device ipaddr>', '<keyword>'): '<value>', ...}
#
# Example:
# {('NEXUS_SWITCH', '1.1.1.1', 'username'): 'admin',
#  ('NEXUS_SWITCH', '1.1.1.1', 'password'): 'mySecretPassword',
#  ('NEXUS_SWITCH', '1.1.1.1', 'compute1'): '1/1', ...}
#
device_dictionary = {}

#
# first_device_ip - IP address of first switch discovered in config
#
# Used for SVI placement when round-robin placement is disabled
#
first_device_ip = None


class CiscoConfigOptions(object):
    """Cisco Configuration Options Class."""

    def __init__(self):
        self._create_device_dictionary()

    def _create_device_dictionary(self):
        """
        Create the device dictionary from the cisco_plugins.ini
        device supported sections. Ex. NEXUS_SWITCH, N1KV.
        """

        global first_device_ip

        multi_parser = cfg.MultiConfigParser()
        read_ok = multi_parser.read(CONF.config_file)

        if len(read_ok) != len(CONF.config_file):
            raise cfg.Error(_("Some config files were not parsed properly"))

        first_device_ip = None
        for parsed_file in multi_parser.parsed:
            for parsed_item in parsed_file.keys():
                dev_id, sep, dev_ip = parsed_item.partition(':')
                if dev_id.lower() == 'n1kv':
                    for dev_key, value in parsed_file[parsed_item].items():
                        if dev_ip and not first_device_ip:
                            first_device_ip = dev_ip
                        device_dictionary[dev_id, dev_ip, dev_key] = value[0]


def get_device_dictionary():
    return device_dictionary
