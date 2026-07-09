# Copyright 2026 Red Hat, LLC
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


EVPN_OPTS = [
    cfg.IntOpt(
        'bgp_as',
        min=1, max=2**32 - 1,
        help=_('BGP Autonomous System number for EVPN')),
    cfg.StrOpt(
        'bgp_local_interface',
        help=_('The local interface name (e.g. eth2) on which to establish '
               'BGP peer session')),
    cfg.StrOpt(
        'frr_vty_socket',
        default='/run/frr',
        help=_('Path to the vtysh socket directory. This is passed '
               'as --vty_socket to the vtysh command.')),
]


def register_opts():
    cfg.CONF.register_opts(EVPN_OPTS, group='ovn_evpn')
