# Copyright 2015 OpenStack Foundation.
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

from neutron.conf.agent.metadata import config as meta_conf
from oslo_config import cfg
from oslo_privsep import priv_context

from neutron._i18n import _

OVS_OPTS = [
    cfg.StrOpt('ovsdb_connection',
               default='unix:/usr/local/var/run/openvswitch/db.sock',
               regex=r'^(tcp|ssl|unix):.+',
               help=_('The connection string for the native OVSDB backend. '
                      'Use tcp:IP:PORT for TCP connections. '
                      'Use unix:FILE for unix domain socket connections.')),
    cfg.IntOpt('ovsdb_connection_timeout',
               default=180,
               help=_('Timeout in seconds for the OVSDB '
                      'connection transaction'))
]


def register_meta_conf_opts(opts, cfg=cfg.CONF, group=None):
    cfg.register_opts(opts, group=group)


def list_metadata_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             meta_conf.SHARED_OPTS,
             meta_conf.METADATA_PROXY_HANDLER_OPTS,
             meta_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS)
         ),
        ('ovs', OVS_OPTS),
        (meta_conf.RATE_LIMITING_GROUP,
         meta_conf.METADATA_RATE_LIMITING_OPTS)
    ]


def get_root_helper(conf):
    return conf.AGENT.root_helper


def setup_privsep():
    priv_context.init(root_helper=shlex.split(get_root_helper(cfg.CONF)))
