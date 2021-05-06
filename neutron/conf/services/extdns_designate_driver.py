# Copyright (c) 2016 IBM
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

from keystoneauth1 import loading
from oslo_config import cfg

from neutron._i18n import _

designate_opts = [
    cfg.StrOpt('url',
               help=_('URL for connecting to designate')),
    cfg.StrOpt('admin_username',
               deprecated_for_removal=True,
               deprecated_since='Xena',
               deprecated_reason=("This option will be completely replaced by "
                                  "keystoneauth parameters."),
               help=_('Username for connecting to designate in admin '
                      'context')),
    cfg.StrOpt('admin_password',
               deprecated_for_removal=True,
               deprecated_since='Xena',
               deprecated_reason=("This option will be completely replaced by "
                                  "keystoneauth parameters."),
               help=_('Password for connecting to designate in admin '
                      'context'),
               secret=True),
    cfg.StrOpt('admin_tenant_id',
               deprecated_for_removal=True,
               deprecated_since='Xena',
               deprecated_reason=("This option will be completely replaced by "
                                  "keystoneauth parameters."),
               help=_('Tenant id for connecting to designate in admin '
                      'context')),
    cfg.StrOpt('admin_tenant_name',
               deprecated_for_removal=True,
               deprecated_since='Xena',
               deprecated_reason=("This option will be completely replaced by "
                                  "keystoneauth parameters."),
               help=_('Tenant name for connecting to designate in admin '
                      'context')),
    cfg.StrOpt('admin_auth_url',
               deprecated_for_removal=True,
               deprecated_since='Xena',
               deprecated_reason=("This option will be completely replaced by "
                                  "keystoneauth parameters."),
               help=_('Authorization URL for connecting to designate in admin '
                      'context')),
    cfg.BoolOpt('allow_reverse_dns_lookup', default=True,
                help=_('Allow the creation of PTR records')),
    cfg.IntOpt(
        'ipv4_ptr_zone_prefix_size', default=24,
        help=_('Number of bits in an ipv4 PTR zone that will be considered '
               'network prefix. It has to align to byte boundary. Minimum '
               'value is 8. Maximum value is 24. As a consequence, range '
               'of values is 8, 16 and 24')),
    cfg.IntOpt(
        'ipv6_ptr_zone_prefix_size', default=120,
        help=_('Number of bits in an ipv6 PTR zone that will be considered '
               'network prefix. It has to align to nyble boundary. Minimum '
               'value is 4. Maximum value is 124. As a consequence, range '
               'of values is 4, 8, 12, 16,..., 124')),
    cfg.StrOpt('ptr_zone_email', default='',
               help=_('The email address to be used when creating PTR zones. '
                      'If not specified, the email address will be '
                      'admin@<dns_domain>')),
]


def register_designate_opts(CONF=cfg.CONF):
    CONF.register_opts(designate_opts, 'designate')
    loading.register_auth_conf_options(CONF, 'designate')
    loading.register_session_conf_options(
        conf=CONF, group='designate',
        deprecated_opts={'cafile': [cfg.DeprecatedOpt('ca_cert')]})
