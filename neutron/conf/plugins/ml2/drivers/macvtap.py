# Copyright (c) 2016 IBM Corp.
#
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

from neutron._i18n import _

DEFAULT_INTERFACE_MAPPINGS = []

macvtap_opts = [
    cfg.ListOpt('physical_interface_mappings',
                default=DEFAULT_INTERFACE_MAPPINGS,
                help=_("Comma-separated list of "
                       "<physical_network>:<physical_interface> tuples "
                       "mapping physical network names to the agent's "
                       "node-specific physical network interfaces to be used "
                       "for flat and VLAN networks. All physical networks "
                       "listed in network_vlan_ranges on the server should "
                       "have mappings to appropriate interfaces on each "
                       "agent.")),
]


def register_macvtap_opts(cfg=cfg.CONF):
    cfg.register_opts(macvtap_opts, "macvtap")
