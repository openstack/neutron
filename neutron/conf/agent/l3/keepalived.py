# Copyright (c) 2015 Red Hat Inc.
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


CLI_OPTS = [
    cfg.StrOpt('router_id', help=_('ID of the router')),
    cfg.StrOpt('namespace', help=_('Namespace of the router')),
    cfg.StrOpt('conf_dir', help=_('Path to the router directory')),
    cfg.StrOpt('monitor_interface', help=_('Interface to monitor')),
    cfg.StrOpt('monitor_cidr', help=_('CIDR to monitor')),
    cfg.StrOpt('pid_file', help=_('Path to PID file for this process')),
    cfg.BoolOpt('enable_conntrackd',
                help=_('Enable conntrackd support'),
                default=False),
    cfg.StrOpt('user', help=_('User (uid or name) running this process '
                              'after its initialization')),
    cfg.StrOpt('group', help=_('Group (gid or name) running this process '
                               'after its initialization'))
]

OPTS = [
    cfg.StrOpt('metadata_proxy_socket',
               default='$state_path/metadata_proxy',
               help=_('Location of Metadata Proxy UNIX domain '
                      'socket'))
]


def register_cli_l3_agent_keepalived_opts(conf=cfg.CONF):
    conf.register_cli_opts(CLI_OPTS)


def register_l3_agent_keepalived_opts(conf=cfg.CONF):
    conf.register_opts(OPTS)
