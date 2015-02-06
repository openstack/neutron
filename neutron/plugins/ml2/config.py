# Copyright (c) 2013 OpenStack Foundation
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


ml2_opts = [
    cfg.ListOpt('type_drivers',
                default=['local', 'flat', 'vlan', 'gre', 'vxlan'],
                help=_("List of network type driver entrypoints to be loaded "
                       "from the neutron.ml2.type_drivers namespace.")),
    cfg.ListOpt('tenant_network_types',
                default=['local'],
                help=_("Ordered list of network_types to allocate as tenant "
                       "networks.")),
    cfg.ListOpt('mechanism_drivers',
                default=[],
                help=_("An ordered list of networking mechanism driver "
                       "entrypoints to be loaded from the "
                       "neutron.ml2.mechanism_drivers namespace.")),
    cfg.ListOpt('extension_drivers',
                default=[],
                help=_("An ordered list of extension driver "
                       "entrypoints to be loaded from the "
                       "neutron.ml2.extension_drivers namespace.")),
    cfg.IntOpt('path_mtu', default=0,
               help=_('The maximum permissible size of an unfragmented '
                      'packet travelling from and to addresses where '
                      'encapsulated Neutron traffic is sent.  If <= 0, '
                      'the path MTU is indeterminate.')),
    cfg.IntOpt('segment_mtu', default=0,
               help=_('The maximum permissible size of an unfragmented '
                      'packet travelling a L2 network segment.  If <= 0, the '
                      'segment MTU is indeterminate.')),
    cfg.ListOpt('physical_network_mtus',
                default=[],
                help=_("A list of mappings of physical networks to MTU "
                       "values. The format of the mapping is "
                       "<physnet>:<mtu val>. This mapping allows "
                       "specifying a physical network MTU value that "
                       "differs from the default segment_mtu value.")),
]


cfg.CONF.register_opts(ml2_opts, "ml2")
