# Copyright 2017 OpenStack Foundation
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

from neutron._i18n import _
from oslo_config import cfg


interface_map = {
    'vsctl': 'neutron.agent.ovsdb.impl_vsctl',
    'native': 'neutron.agent.ovsdb.impl_idl',
}


API_OPTS = [
    cfg.StrOpt('ovsdb_interface',
               deprecated_for_removal=True,
               choices=interface_map.keys(),
               default='native',
               help=_('The interface for interacting with the OVSDB')),
    cfg.StrOpt('ovsdb_connection',
               default='tcp:127.0.0.1:6640',
               help=_('The connection string for the OVSDB backend. '
                      'Will be used by ovsdb-client when monitoring and '
                      'used for the all ovsdb commands when native '
                      'ovsdb_interface is enabled'
                      )),
    cfg.StrOpt('ssl_key_file',
               help=_('The SSL private key file to use when interacting with '
                      'OVSDB. Required when using an "ssl:" prefixed '
                      'ovsdb_connection'
                      )),
    cfg.StrOpt('ssl_cert_file',
               help=_('The SSL certificate file to use when interacting '
                      'with OVSDB. Required when using an "ssl:" prefixed '
                      'ovsdb_connection'
                      )),
    cfg.StrOpt('ssl_ca_cert_file',
               help=_('The Certificate Authority (CA) certificate to use '
                      'when interacting with OVSDB.  Required when using an '
                      '"ssl:" prefixed ovsdb_connection'
                      )),
]


def register_ovsdb_api_opts(cfg=cfg.CONF):
    cfg.register_opts(API_OPTS, 'OVS')
