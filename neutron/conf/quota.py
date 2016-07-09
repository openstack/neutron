# Copyright 2016 Intel Corporation.
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

from neutron._i18n import _

QUOTA_DB_MODULE = 'neutron.db.quota.driver'
QUOTA_DB_DRIVER = '%s.DbQuotaDriver' % QUOTA_DB_MODULE
QUOTA_CONF_DRIVER = 'neutron.quota.ConfDriver'
QUOTAS_CFG_GROUP = 'QUOTAS'


# quota_opts from neutron/quota/__init__.py
# renamed quota_opts to core_quota_opts
core_quota_opts = [
    cfg.IntOpt('default_quota',
               default=-1,
               help=_('Default number of resource allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_network',
               default=10,
               help=_('Number of networks allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_subnet',
               default=10,
               help=_('Number of subnets allowed per tenant, '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_port',
               default=50,
               help=_('Number of ports allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.StrOpt('quota_driver',
               default=QUOTA_DB_DRIVER,
               help=_('Default driver to use for quota checks.')),
    cfg.BoolOpt('track_quota_usage',
                default=True,
                help=_('Keep in track in the database of current resource '
                       'quota usage. Plugins which do not leverage the '
                       'neutron database should set this flag to False.')),
]

# security_group_quota_opts from neutron/extensions/securitygroup.py
security_group_quota_opts = [
    cfg.IntOpt('quota_security_group',
               default=10,
               help=_('Number of security groups allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_security_group_rule',
               default=100,
               help=_('Number of security rules allowed per tenant. '
                      'A negative value means unlimited.')),
]

# l3_quota_opts from neutron/extensions/l3.py
l3_quota_opts = [
    cfg.IntOpt('quota_router',
               default=10,
               help=_('Number of routers allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_floatingip',
               default=50,
               help=_('Number of floating IPs allowed per tenant. '
                      'A negative value means unlimited.')),
]

# rbac_quota_opts from neutron/extensions/rbac.py
rbac_quota_opts = [
    cfg.IntOpt('quota_rbac_policy', default=10,
               deprecated_name='quota_rbac_entry',
               help=_('Default number of RBAC entries allowed per tenant. '
                      'A negative value means unlimited.'))
]


def register_quota_opts(opts, cfg=cfg.CONF):
    cfg.register_opts(opts, QUOTAS_CFG_GROUP)
