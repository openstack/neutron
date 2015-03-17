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

from neutron.common import utils


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


DRIVER_OPTS = [
    cfg.BoolOpt('metadata_proxy_watch_log',
                default=None,
                help=_("Enable/Disable log watch by metadata proxy. It "
                       "should be disabled when metadata_proxy_user/group "
                       "is not allowed to read/write its log file and "
                       "copytruncate logrotate option must be used if "
                       "logrotate is enabled on metadata proxy log "
                       "files. Option default value is deduced from "
                       "metadata_proxy_user: watch log is enabled if "
                       "metadata_proxy_user is agent effective user "
                       "id/name.")),
]


METADATA_PROXY_HANDLER_OPTS = [
     cfg.StrOpt('admin_user',
                help=_("Admin user")),
     cfg.StrOpt('admin_password',
                help=_("Admin password"),
                secret=True),
     cfg.StrOpt('admin_tenant_name',
                help=_("Admin tenant name")),
     cfg.StrOpt('auth_url',
                help=_("Authentication URL")),
     cfg.StrOpt('auth_strategy', default='keystone',
                help=_("The type of authentication to use")),
     cfg.StrOpt('auth_region',
                help=_("Authentication region")),
     cfg.BoolOpt('auth_insecure',
                 default=False,
                 help=_("Turn off verification of the certificate for"
                        " ssl")),
     cfg.StrOpt('auth_ca_cert',
                help=_("Certificate Authority public key (CA cert) "
                       "file for ssl")),
     cfg.StrOpt('endpoint_type',
                default='adminURL',
                help=_("Network service endpoint type to pull from "
                       "the keystone catalog")),
     cfg.StrOpt('nova_metadata_ip', default='127.0.0.1',
                help=_("IP address used by Nova metadata server.")),
     cfg.IntOpt('nova_metadata_port',
                default=8775,
                help=_("TCP Port used by Nova metadata server.")),
     cfg.StrOpt('metadata_proxy_shared_secret',
                default='',
                help=_('Shared secret to sign instance-id request'),
                secret=True),
     cfg.StrOpt('nova_metadata_protocol',
                default='http',
                choices=['http', 'https'],
                help=_("Protocol to access nova metadata, http or https")),
     cfg.BoolOpt('nova_metadata_insecure', default=False,
                 help=_("Allow to perform insecure SSL (https) requests to "
                        "nova metadata")),
     cfg.StrOpt('nova_client_cert',
                default='',
                help=_("Client certificate for nova metadata api server.")),
     cfg.StrOpt('nova_client_priv_key',
                default='',
                help=_("Private key of client certificate."))
]

DEDUCE_MODE = 'deduce'
USER_MODE = 'user'
GROUP_MODE = 'group'
ALL_MODE = 'all'
SOCKET_MODES = (DEDUCE_MODE, USER_MODE, GROUP_MODE, ALL_MODE)


UNIX_DOMAIN_METADATA_PROXY_OPTS = [
    cfg.StrOpt('metadata_proxy_socket_mode',
               default=DEDUCE_MODE,
               choices=SOCKET_MODES,
               help=_("Metadata Proxy UNIX domain socket mode, 3 values "
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
               default=utils.cpu_count() // 2,
               help=_('Number of separate worker processes for metadata '
                      'server')),
    cfg.IntOpt('metadata_backlog',
               default=4096,
               help=_('Number of backlog requests to configure the '
                      'metadata server socket with'))
]
