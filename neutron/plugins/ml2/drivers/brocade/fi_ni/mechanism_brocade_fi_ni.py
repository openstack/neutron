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

"""Implementation of Brocade ML2 Mechanism driver for ICX and MLX."""

from networking_brocade.mlx.ml2.fi_ni import mechanism_brocade_fi_ni
from oslo_config import cfg

SWITCHES = [
    cfg.StrOpt(
        'switch_names',
        default='',
        help=('Switches connected to the compute nodes'))]

ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=('The SSH password to use')),
               cfg.StrOpt('physical_networks', default='',
                          help=('Allowed physical networks')),
               cfg.StrOpt('ports', default='',
                          help=('Ports')),
               cfg.StrOpt('transport', default='SSH',
                          choices=('SSH', 'TELNET'),
                          help=('Protocol used to communicate with Switch')),
               cfg.StrOpt('ostype', default='NI', choices=('NI', 'FI'),
                          help=('OS type of the device.')),
               ]
cfg.CONF.register_opts(SWITCHES, 'ml2_brocade_fi_ni')
cfg.CONF.register_opts(ML2_BROCADE, 'ML2_BROCADE_MLX_EXAMPLE')


class BrocadeFiNiMechanism(mechanism_brocade_fi_ni.BrocadeFiNiMechanism):
    def __init__(self):
        self._switch_names = cfg.CONF.ml2_brocade_fi_ni.switch_names
        switches = [x.strip() for x in self._switch_names.split(',')]
        for switch in switches:
            cfg.CONF.register_opts(ML2_BROCADE, switch)
        super(BrocadeFiNiMechanism, self).__init__()
