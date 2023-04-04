# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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
#


from oslo_config import cfg

from neutron._i18n import _


security_group_opts = [
    cfg.StrOpt(
        'firewall_driver',
        help=_('Driver for security groups firewall in the L2 agent')),
    cfg.BoolOpt(
        'enable_security_group',
        default=True,
        help=_(
            'Controls whether the neutron security group API is enabled '
            'in the server. It should be false when using no security '
            'groups or using the Nova security group API.')),
    cfg.BoolOpt(
        'enable_ipset',
        default=True,
        help=_('Use IPsets to speed-up the iptables based security groups. '
               'Enabling IPset support requires that ipset is installed on '
               'the L2 agent node.')),
    cfg.ListOpt(
        'permitted_ethertypes',
        default=[],
        help=_('Comma-separated list of ethertypes to be permitted, in '
               'hexadecimal (starting with "0x"). For example, "0x4008" '
               'to permit InfiniBand.'))
]


def register_securitygroups_opts(cfg=cfg.CONF):
    cfg.register_opts(security_group_opts, 'SECURITYGROUP')
