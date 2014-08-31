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

from oslo.config import cfg


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
]


cfg.CONF.register_opts(ml2_opts, "ml2")
