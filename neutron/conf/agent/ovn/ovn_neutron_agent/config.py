# Copyright (c) 2023 Red Hat, Inc.
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

import itertools
import shlex

from neutron.conf.agent import ovsdb_api
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from oslo_config import cfg
from oslo_privsep import priv_context

from neutron._i18n import _


OVS_OPTS = [
    cfg.IntOpt(
        'ovsdb_connection_timeout',
        default=180,
        help=_('Timeout in seconds for the OVSDB connection transaction'))
]


def list_ovn_neutron_agent_opts():
    return [
        ('ovn', ovn_conf.ovn_opts),
        ('ovs', itertools.chain(OVS_OPTS,
                                ovsdb_api.API_OPTS,
                                )
         ),
    ]


def register_opts():
    cfg.CONF.register_opts(ovn_conf.ovn_opts, group='ovn')
    cfg.CONF.register_opts(OVS_OPTS, group='ovs')
    cfg.CONF.register_opts(ovsdb_api.API_OPTS, group='ovs')


def get_root_helper(conf):
    return conf.AGENT.root_helper


def setup_privsep():
    priv_context.init(root_helper=shlex.split(get_root_helper(cfg.CONF)))
