# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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

from oslo.config import cfg

midonet_opts = [
    cfg.StrOpt('midonet_uri', default='http://localhost:8080/midonet-api',
               help=_('MidoNet API server URI.')),
    cfg.StrOpt('username', default='admin',
               help=_('MidoNet admin username.')),
    cfg.StrOpt('password', default='passw0rd',
               secret=True,
               help=_('MidoNet admin password.')),
    cfg.StrOpt('project_id',
               default='77777777-7777-7777-7777-777777777777',
               help=_('ID of the project that MidoNet admin user'
                      'belongs to.')),
    cfg.StrOpt('provider_router_id',
               help=_('Virtual provider router ID.')),
    cfg.StrOpt('mode',
               default='dev',
               help=_('Operational mode. Internal dev use only.')),
    cfg.StrOpt('midonet_host_uuid_path',
               default='/etc/midolman/host_uuid.properties',
               help=_('Path to midonet host uuid file'))
]


cfg.CONF.register_opts(midonet_opts, "MIDONET")
