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

from neutron_lib import constants as p_const
from oslo_config import cfg

from neutron._i18n import _


gre_opts = [
    cfg.ListOpt('tunnel_id_ranges',
                default=[],
                help=_("Comma-separated list of <tun_min>:<tun_max> tuples "
                       "enumerating ranges of GRE tunnel IDs that are "
                       "available for tenant network allocation"))
]

flat_opts = [
    cfg.ListOpt('flat_networks',
                default='*',
                help=_("List of physical_network names with which flat "
                       "networks can be created. Use default '*' to allow "
                       "flat networks with arbitrary physical_network names. "
                       "Use an empty list to disable flat networks."))
]

geneve_opts = [
    cfg.ListOpt('vni_ranges',
                default=[],
                help=_("Comma-separated list of <vni_min>:<vni_max> tuples "
                       "enumerating ranges of Geneve VNI IDs that are "
                       "available for tenant network allocation")),
    cfg.IntOpt('max_header_size',
               default=p_const.GENEVE_ENCAP_MIN_OVERHEAD,
               help=_("Geneve encapsulation header size is dynamic, this "
                      "value is used to calculate the maximum MTU "
                      "for the driver. "
                      "This is the sum of the sizes of the outer "
                      "ETH + IP + UDP + GENEVE header sizes. "
                      "The default size for this field is 50, which is the "
                      "size of the Geneve header without any additional "
                      "option headers.")),
]

vxlan_opts = [
    cfg.ListOpt('vni_ranges',
                default=[],
                help=_("Comma-separated list of <vni_min>:<vni_max> tuples "
                       "enumerating ranges of VXLAN VNI IDs that are "
                       "available for tenant network allocation")),
    cfg.StrOpt('vxlan_group',
               help=_("Multicast group for VXLAN. When configured, will "
                      "enable sending all broadcast traffic to this multicast "
                      "group. When left unconfigured, will disable multicast "
                      "VXLAN mode.")),
]

vlan_opts = [
    cfg.ListOpt('network_vlan_ranges',
                default=[],
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> or "
                       "<physical_network> specifying physical_network names "
                       "usable for VLAN provider and tenant networks, as "
                       "well as ranges of VLAN tags on each available for "
                       "allocation to tenant networks."))
]


def register_ml2_drivers_gre_opts(cfg=cfg.CONF):
    cfg.register_opts(gre_opts, "ml2_type_gre")


def register_ml2_drivers_flat_opts(cfg=cfg.CONF):
    cfg.register_opts(flat_opts, "ml2_type_flat")


def register_ml2_drivers_geneve_opts(cfg=cfg.CONF):
    cfg.register_opts(geneve_opts, "ml2_type_geneve")


def register_ml2_drivers_vxlan_opts(cfg=cfg.CONF):
    cfg.register_opts(vxlan_opts, "ml2_type_vxlan")


def register_ml2_drivers_vlan_opts(cfg=cfg.CONF):
    cfg.register_opts(vlan_opts, "ml2_type_vlan")
