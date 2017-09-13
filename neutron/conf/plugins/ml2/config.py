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

from neutron._i18n import _

ml2_opts = [
    cfg.ListOpt('type_drivers',
                default=['local', 'flat', 'vlan', 'gre', 'vxlan', 'geneve'],
                help=_("List of network type driver entrypoints to be loaded "
                       "from the neutron.ml2.type_drivers namespace.")),
    cfg.ListOpt('tenant_network_types',
                default=['local'],
                help=_("Ordered list of network_types to allocate as tenant "
                       "networks. The default value 'local' is useful for "
                       "single-box testing but provides no connectivity "
                       "between hosts.")),
    cfg.ListOpt('mechanism_drivers',
                default=[],
                help=_("An ordered list of networking mechanism driver "
                       "entrypoints to be loaded from the "
                       "neutron.ml2.mechanism_drivers namespace.")),
    cfg.ListOpt('extension_drivers',
                default=[],
                help=_("An ordered list of extension driver "
                       "entrypoints to be loaded from the "
                       "neutron.ml2.extension_drivers namespace. "
                       "For example: extension_drivers = port_security,qos")),
    cfg.IntOpt('path_mtu', default=0,
               help=_('Maximum size of an IP packet (MTU) that can traverse '
                      'the underlying physical network infrastructure without '
                      'fragmentation when using an overlay/tunnel protocol. '
                      'This option allows specifying a physical network MTU '
                      'value that differs from the default global_physnet_mtu '
                      'value.')),
    cfg.ListOpt('physical_network_mtus',
                default=[],
                help=_("A list of mappings of physical networks to MTU "
                       "values. The format of the mapping is "
                       "<physnet>:<mtu val>. This mapping allows "
                       "specifying a physical network MTU value that "
                       "differs from the default global_physnet_mtu value.")),
    cfg.StrOpt('external_network_type',
               help=_("Default network type for external networks when no "
                      "provider attributes are specified. By default it is "
                      "None, which means that if provider attributes are not "
                      "specified while creating external networks then they "
                      "will have the same type as tenant networks. Allowed "
                      "values for external_network_type config option depend "
                      "on the network type values configured in type_drivers "
                      "config option.")),
    cfg.IntOpt('overlay_ip_version',
               default=4,
               help=_("IP version of all overlay (tunnel) network endpoints. "
                      "Use a value of 4 for IPv4 or 6 for IPv6."))
]


def register_ml2_plugin_opts(cfg=cfg.CONF):
    cfg.register_opts(ml2_opts, "ml2")
