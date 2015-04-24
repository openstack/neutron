# Copyright 2015 Brocade Communications Systems, Inc.
# All rights reserved.
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
"""Implementation of Brocade L3RouterPlugin for MLX switches."""

from networking_brocade.mlx.services.l3_router.brocade import (
    l3_router_plugin as plugin)
from oslo_config import cfg

SWITCHES = [
    cfg.StrOpt(
        'switch_names',
        default='',
        help=('Switches connected to the compute nodes'))]

L3_BROCADE = [cfg.StrOpt('address', default='',
                         help=('The IP address of the MLX switch')),
              cfg.StrOpt('username', default='admin',
                         help=('The SSH username of the switch')),
              cfg.StrOpt('password', default='password', secret=True,
                         help=('The SSH password of the switch')),
              cfg.StrOpt('physical_networks', default='',
                         help=('Allowed physical networks where VLAN can '
                               'be configured on this switch')),
              cfg.StrOpt('ports', default='',
                         help=('Ports to be tagged in the VLAN being '
                               'configured on the switch')),
              ]
cfg.CONF.register_opts(SWITCHES, 'l3_brocade_mlx')
cfg.CONF.register_opts(L3_BROCADE, 'L3_BROCADE_MLX_EXAMPLE')


class BrocadeRouterPlugin(plugin.BrocadeRouterPlugin):
    def __init__(self):
        self._switch_names = cfg.CONF.l3_brocade_mlx.switch_names
        switches = [x.strip() for x in self._switch_names.split(',')]
        for switch in switches:
            cfg.CONF.register_opts(L3_BROCADE, switch)
        super(BrocadeRouterPlugin, self).__init__()
