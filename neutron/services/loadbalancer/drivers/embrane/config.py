# Copyright 2014 Embrane, Inc.
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

# User may want to use LB service together with the L3 plugin, but using
# different resources. The service will inherit the configuration from the
# L3 heleos plugin if present and not overridden.
heleos_opts = [
    cfg.StrOpt('esm_mgmt',
               help=_('ESM management root address')),
    cfg.StrOpt('admin_username',
               help=_('ESM admin username.')),
    cfg.StrOpt('admin_password',
               secret=True,
               help=_('ESM admin password.')),
    cfg.StrOpt('lb_image',
               help=_('Load Balancer image id (Embrane LB)')),
    cfg.StrOpt('inband_id',
               help=_('In band Security Zone id for LBs')),
    cfg.StrOpt('oob_id',
               help=_('Out of band Security Zone id for LBs')),
    cfg.StrOpt('mgmt_id',
               help=_('Management Security Zone id for LBs')),
    cfg.StrOpt('dummy_utif_id',
               help=_('Dummy user traffic Security Zone id for LBs')),
    cfg.StrOpt('resource_pool_id',
               help=_('Shared resource pool id')),
    cfg.StrOpt('lb_flavor', default="small",
               help=_('choose LB image flavor to use, accepted values: small, '
                      'medium')),
    cfg.IntOpt('sync_interval', default=60,
               help=_('resource synchronization interval in seconds')),
    cfg.BoolOpt('async_requests',
                help=_('Define if the requests have '
                       'run asynchronously or not')),
]

cfg.CONF.register_opts(heleos_opts, 'heleoslb')
