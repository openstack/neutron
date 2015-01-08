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


UNIX_DOMAIN_METADATA_PROXY_OPTS = [
    cfg.StrOpt('metadata_proxy_socket',
               default='$state_path/metadata_proxy',
               help=_('Location for Metadata Proxy UNIX domain socket')),
    cfg.IntOpt('metadata_workers',
               default=utils.cpu_count() // 2,
               help=_('Number of separate worker processes for metadata '
                      'server')),
    cfg.IntOpt('metadata_backlog',
               default=4096,
               help=_('Number of backlog requests to configure the '
                      'metadata server socket with'))
]
