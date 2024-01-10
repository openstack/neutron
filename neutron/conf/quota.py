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


QUOTA_DB_DIRECTORY = 'neutron.db.quota.'
QUOTA_DB_DRIVER_LEGACY = QUOTA_DB_DIRECTORY + 'driver.DbQuotaDriver'
QUOTA_DB_DRIVER_NO_LOCK = (QUOTA_DB_DIRECTORY +
                           'driver_nolock.DbQuotaNoLockDriver')
QUOTA_DB_DRIVER_NULL = QUOTA_DB_DIRECTORY + 'driver_null.DbQuotaDriverNull'

QUOTA_DB_DRIVER = QUOTA_DB_DRIVER_NO_LOCK
QUOTAS_CFG_GROUP = 'QUOTAS'

DEFAULT_QUOTA = -1
DEFAULT_QUOTA_NETWORK = 100
DEFAULT_QUOTA_SUBNET = 100
DEFAULT_QUOTA_PORT = 500
DEFAULT_QUOTA_SG = 10
DEFAULT_QUOTA_SG_RULE = 100
DEFAULT_QUOTA_ROUTER = 10
DEFAULT_QUOTA_FIP = 50
DEFAULT_QUOTA_RBAC = 10


# quota_opts from neutron/quota/__init__.py
# renamed quota_opts to core_quota_opts
core_quota_opts = [
    cfg.IntOpt('default_quota',
               default=DEFAULT_QUOTA,
               help=_('Default number of resources allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_network',
               default=DEFAULT_QUOTA_NETWORK,
               help=_('Number of networks allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_subnet',
               default=DEFAULT_QUOTA_SUBNET,
               help=_('Number of subnets allowed per tenant, '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_port',
               default=DEFAULT_QUOTA_PORT,
               help=_('Number of ports allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.StrOpt('quota_driver',
               default=QUOTA_DB_DRIVER,
               help=_('Default driver to use for quota checks.')),
    cfg.BoolOpt('track_quota_usage',
                default=True,
                help=_('When set to True, quota usage will be tracked in the '
                       'Neutron database for each resource, by directly '
                       'mapping to a data model class, for example, '
                       'networks, subnets, ports, etc. '
                       'When set to False, quota usage will be tracked by '
                       'the quota engine as a count of the object type '
                       'directly. '
                       'For more information, see the Quota Management '
                       'and Enforcement guide.')),
]

# security_group_quota_opts from neutron/extensions/securitygroup.py
security_group_quota_opts = [
    cfg.IntOpt('quota_security_group',
               default=DEFAULT_QUOTA_SG,
               help=_('Number of security groups allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_security_group_rule',
               default=DEFAULT_QUOTA_SG_RULE,
               help=_('Number of security group rules allowed per tenant. '
                      'A negative value means unlimited.')),
]

# l3_quota_opts from neutron/extensions/l3.py
l3_quota_opts = [
    cfg.IntOpt('quota_router',
               default=DEFAULT_QUOTA_ROUTER,
               help=_('Number of routers allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_floatingip',
               default=DEFAULT_QUOTA_FIP,
               help=_('Number of floating IPs allowed per tenant. '
                      'A negative value means unlimited.')),
]

# rbac_quota_opts from neutron/extensions/rbac.py
rbac_quota_opts = [
    cfg.IntOpt('quota_rbac_policy', default=DEFAULT_QUOTA_RBAC,
               help=_('Default number of RBAC entries allowed per tenant. '
                      'A negative value means unlimited.'))
]


def register_quota_opts(opts, cfg=cfg.CONF):
    cfg.register_opts(opts, QUOTAS_CFG_GROUP)
