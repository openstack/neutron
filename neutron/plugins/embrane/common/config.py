# Copyright 2013 Embrane, Inc.
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

from oslo_config import cfg


heleos_opts = [
    cfg.StrOpt('esm_mgmt',
               help=_('ESM management root address')),
    cfg.StrOpt('admin_username', default='admin',
               help=_('ESM admin username.')),
    cfg.StrOpt('admin_password',
               secret=True,
               help=_('ESM admin password.')),
    cfg.StrOpt('router_image',
               help=_('Router image id (Embrane FW/VPN)')),
    cfg.StrOpt('inband_id',
               help=_('In band Security Zone id')),
    cfg.StrOpt('oob_id',
               help=_('Out of band Security Zone id')),
    cfg.StrOpt('mgmt_id',
               help=_('Management Security Zone id')),
    cfg.StrOpt('dummy_utif_id',
               help=_('Dummy user traffic Security Zone id')),
    cfg.StrOpt('resource_pool_id', default='default',
               help=_('Shared resource pool id')),
    cfg.BoolOpt('async_requests', default=True,
                help=_('Define if the requests have '
                       'run asynchronously or not')),
]


cfg.CONF.register_opts(heleos_opts, "heleos")
