# Copyright 2014 Brocade Communications System, Inc.
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


"""Implentation of Brocade ML2 Mechanism driver for ML2 Plugin."""

from oslo_config import cfg

ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=_('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=_('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=_('The SSH password to use')),
               cfg.StrOpt('physical_networks', default='',
                          help=_('Allowed physical networks')),
               cfg.StrOpt('ostype', default='NOS',
                          help=_('OS Type of the switch')),
               cfg.StrOpt('osversion', default='4.0.0',
                          help=_('OS Version number'))
               ]

cfg.CONF.register_opts(ML2_BROCADE, "ml2_brocade")
