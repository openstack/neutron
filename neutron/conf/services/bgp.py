# Copyright 2025 Red Hat, Inc.
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

bgp_opts = [
    cfg.StrOpt('main_router_name',
               default='bgp-lr-main',
               help=_('Name of the main BGP router.')),
    cfg.IntOpt('main_router_vrf_id',
               default=42,
               help=_('VRF ID for the main BGP router.')),
    cfg.IntOpt('chassis_router_vrf_id',
               default=10,
               help=_('VRF ID for the chassis BGP router. This VRF ID is used '
                      'to learn default routes for the egress traffic out '
                      'from the chassis.')),
]


def get_main_router_name():
    return cfg.CONF.bgp.main_router_name


def get_main_router_vrf_id():
    return cfg.CONF.bgp.main_router_vrf_id


def get_chassis_router_vrf_id():
    return cfg.CONF.bgp.chassis_router_vrf_id


def register_opts(conf):
    conf.register_opts(bgp_opts, group='bgp')
