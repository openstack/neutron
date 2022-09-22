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

from oslo_config import cfg

from neutron._i18n import _

DEDUCE_MODE = 'deduce'
USER_MODE = 'user'
GROUP_MODE = 'group'
ALL_MODE = 'all'
SOCKET_MODES = (DEDUCE_MODE, USER_MODE, GROUP_MODE, ALL_MODE)
RATE_LIMITING_GROUP = 'metadata_rate_limiting'

SHARED_OPTS = [
    cfg.StrOpt('metadata_proxy_socket',
               default='$state_path/metadata_proxy',
               help=_('Location for Metadata Proxy UNIX domain socket.')),
    cfg.StrOpt('metadata_proxy_user',
               default='',
               help=_("User (uid or name) running metadata proxy after "
                      "its initialization (if empty: agent effective "
                      "user).")),
    cfg.StrOpt('metadata_proxy_group',
               default='',
               help=_("Group (gid or name) running metadata proxy after "
                      "its initialization (if empty: agent effective "
                      "group)."))
]


METADATA_PROXY_HANDLER_OPTS = [
    cfg.StrOpt('auth_ca_cert',
               help=_("Certificate Authority public key (CA cert) "
                      "file for ssl")),
    cfg.HostAddressOpt('nova_metadata_host',
                       default='127.0.0.1',
                       help=_("IP address or DNS name of Nova metadata "
                              "server.")),
    cfg.PortOpt('nova_metadata_port',
                default=8775,
                help=_("TCP Port used by Nova metadata server.")),
    cfg.StrOpt('metadata_proxy_shared_secret',
               default='',
               help=_('When proxying metadata requests, Neutron signs the '
                      'Instance-ID header with a shared secret to prevent '
                      'spoofing. You may select any string for a secret, '
                      'but it must match here and in the configuration used '
                      'by the Nova metadata server. NOTE: Nova uses the same '
                      'config key, but in [neutron] section.'),
               secret=True),
    cfg.StrOpt('nova_metadata_protocol',
               default='http',
               choices=['http', 'https'],
               help=_("Protocol to access Nova metadata, http or https")),
    cfg.BoolOpt('nova_metadata_insecure', default=False,
                help=_("Allow to perform insecure SSL (https) requests to "
                       "Nova metadata")),
    cfg.StrOpt('nova_client_cert',
               default='',
               help=_("Client certificate for Nova metadata api server.")),
    cfg.StrOpt('nova_client_priv_key',
               default='',
               help=_("Private key of client certificate."))
]


UNIX_DOMAIN_METADATA_PROXY_OPTS = [
    cfg.StrOpt('metadata_proxy_socket_mode',
               default=DEDUCE_MODE,
               choices=SOCKET_MODES,
               help=_("Metadata Proxy UNIX domain socket mode, 4 values "
                      "allowed: "
                      "'deduce': deduce mode from metadata_proxy_user/group "
                      "values, "
                      "'user': set metadata proxy socket mode to 0o644, to "
                      "use when metadata_proxy_user is agent effective user "
                      "or root, "
                      "'group': set metadata proxy socket mode to 0o664, to "
                      "use when metadata_proxy_group is agent effective "
                      "group or root, "
                      "'all': set metadata proxy socket mode to 0o666, to use "
                      "otherwise.")),
    cfg.IntOpt('metadata_workers',
               sample_default='<num_of_cpus> / 2',
               help=_('Number of separate worker processes for metadata '
                      'server (defaults to 2 when used with ML2/OVN and half '
                      'of the number of CPUs with other backend drivers)')),
    cfg.IntOpt('metadata_backlog',
               default=4096,
               help=_('Number of backlog requests to configure the '
                      'metadata server socket with'))
]


METADATA_RATE_LIMITING_OPTS = [
    cfg.BoolOpt('rate_limit_enabled',
                default=False,
                help=_('Enable rate limiting on the metadata API.')),
    cfg.ListOpt('ip_versions',
                default=['4'],
                help=_('Comma separated list of the metadata address IP '
                       'versions (4, 6) for which rate limiting will be '
                       'enabled. The default is to rate limit only for the '
                       'metadata IPv4 address. NOTE: at the moment, the open '
                       'source version of HAProxy only allows us to rate '
                       'limit for IPv4 or IPv6, but not both at the same '
                       'time.')),
    cfg.IntOpt('base_window_duration',
               default=10,
               help=_("Duration (seconds) of the base window on the "
                      "metadata API.")),
    cfg.IntOpt('base_query_rate_limit',
               default=10,
               help=_("Max number of queries to accept during the base "
                      "window.")),
    cfg.IntOpt('burst_window_duration',
               default=10,
               help=_("Duration (seconds) of the burst window on the "
                      "metadata API.")),
    cfg.IntOpt('burst_query_rate_limit',
               default=10,
               help=_("Max number of queries to accept during the burst "
                      "window.")),
]


def register_meta_conf_opts(opts, cfg=cfg.CONF, group=None):
    cfg.register_opts(opts, group=group)
