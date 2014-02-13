# Copyright (c) 2014 OpenStack Foundation
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
#
# @author: Arvind Somya (asomya@cisco.com), Cisco Systems Inc.

from oslo.config import cfg


apic_opts = [
    cfg.StrOpt('apic_host',
               help=_("Host name or IP Address of the APIC controller")),
    cfg.StrOpt('apic_username',
               help=_("Username for the APIC controller")),
    cfg.StrOpt('apic_password',
               help=_("Password for the APIC controller"), secret=True),
    cfg.StrOpt('apic_port',
               help=_("Communication port for the APIC controller")),
    cfg.StrOpt('apic_vmm_provider', default='VMware',
               help=_("Name for the VMM domain provider")),
    cfg.StrOpt('apic_vmm_domain', default='openstack',
               help=_("Name for the VMM domain to be created for Openstack")),
    cfg.StrOpt('apic_vlan_ns_name', default='openstack_ns',
               help=_("Name for the vlan namespace to be used for openstack")),
    cfg.StrOpt('apic_vlan_range', default='2:4093',
               help=_("Range of VLAN's to be used for Openstack")),
    cfg.StrOpt('apic_node_profile', default='openstack_profile',
               help=_("Name of the node profile to be created")),
    cfg.StrOpt('apic_entity_profile', default='openstack_entity',
               help=_("Name of the entity profile to be created")),
    cfg.StrOpt('apic_function_profile', default='openstack_function',
               help=_("Name of the function profile to be created")),
    cfg.BoolOpt('apic_clear_node_profiles', default=False,
                help=_("Clear the node profiles on the APIC at startup "
                       "(mainly used for testing)")),
]


cfg.CONF.register_opts(apic_opts, "ml2_cisco_apic")


def get_switch_and_port_for_host(host_id):
    for switch, connected in _switch_dict.items():
        for port, hosts in connected.items():
            if host_id in hosts:
                return switch, port


_switch_dict = {}


def create_switch_dictionary():
    multi_parser = cfg.MultiConfigParser()
    read_ok = multi_parser.read(cfg.CONF.config_file)

    if len(read_ok) != len(cfg.CONF.config_file):
        raise cfg.Error(_("Some config files were not parsed properly"))

    for parsed_file in multi_parser.parsed:
        for parsed_item in parsed_file.keys():
            if parsed_item.startswith('apic_switch'):
                switch, switch_id = parsed_item.split(':')
                if switch.lower() == 'apic_switch':
                    _switch_dict[switch_id] = {}
                    port_cfg = parsed_file[parsed_item].items()
                    for host_list, port in port_cfg:
                        hosts = host_list.split(',')
                        port = port[0]
                        _switch_dict[switch_id][port] = hosts

    return _switch_dict
