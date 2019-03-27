# Copyright (c) 2019 Red Hat, Inc.
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

from neutron_lib import constants as n_const
from oslo_config import cfg

from neutron._i18n import _

conntrack_helper_opts = [
    cfg.ListOpt('allowed_conntrack_helpers',
                default=[
                    {'amanda': n_const.PROTO_NAME_TCP},
                    {'ftp': n_const.PROTO_NAME_TCP},
                    {'h323': n_const.PROTO_NAME_UDP},
                    {'h323': n_const.PROTO_NAME_TCP},
                    {'irc': n_const.PROTO_NAME_TCP},
                    {'netbios-ns': n_const.PROTO_NAME_UDP},
                    {'pptp': n_const.PROTO_NAME_TCP},
                    {'sane': n_const.PROTO_NAME_TCP},
                    {'sip': n_const.PROTO_NAME_UDP},
                    {'sip': n_const.PROTO_NAME_TCP},
                    {'snmp': n_const.PROTO_NAME_UDP},
                    {'tftp': n_const.PROTO_NAME_UDP}
                ],
                item_type=cfg.types.Dict(),
                sample_default=[
                    {'tftp': 'udp'},
                    {'ftp': 'tcp'},
                    {'sip': 'tcp'},
                    {'sip': 'udp'}
                ],
                help=_('Defines the allowed conntrack helpers, and '
                       'conntack helper module protocol constraints.')
                )
]


def register_conntrack_helper_opts(cfg=cfg.CONF):
    cfg.register_opts(conntrack_helper_opts)
