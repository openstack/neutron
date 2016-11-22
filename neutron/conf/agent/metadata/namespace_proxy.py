# Copyright 2016 New Dream Network, LLC (DreamHost)
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

OPTS = [
    cfg.StrOpt('network_id',
               help=_('Network that will have instance metadata '
                      'proxied.')),
    cfg.StrOpt('router_id',
               help=_('Router that will have connected instances\' '
                      'metadata proxied.')),
    cfg.StrOpt('pid_file',
               help=_('Location of pid file of this process.')),
    cfg.BoolOpt('daemonize',
                default=True,
                help=_('Run as daemon.')),
    cfg.PortOpt('metadata_port',
                default=9697,
                help=_('TCP Port to listen for metadata server'
                       'requests.')),
    cfg.StrOpt('metadata_proxy_socket',
               default='$state_path/metadata_proxy',
               help=_('Location of Metadata Proxy UNIX domain '
                      'socket')),
    cfg.StrOpt('metadata_proxy_user',
               help=_('User (uid or name) running metadata proxy after '
                      'its initialization')),
    cfg.StrOpt('metadata_proxy_group',
               help=_('Group (gid or name) running metadata proxy after '
                      'its initialization')),
    cfg.BoolOpt('metadata_proxy_watch_log',
                default=True,
                help=_('Watch file log. Log watch should be disabled when '
                       'metadata_proxy_user/group has no read/write '
                       'permissions on metadata proxy log file.')),
]


def register_namespace_proxy_opts(cfg=cfg.CONF):
    cfg.register_cli_opts(OPTS)
