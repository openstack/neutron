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

from oslo_config import cfg

from midonet.neutron import plugin

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
               help=_('ID of the project that MidoNet admin user '
                      'belongs to.'))
]


cfg.CONF.register_opts(midonet_opts, "MIDONET")


# Derives from `object` (via at least NeutronDbPluginV2), but pylint
# can't see that without having the midonet libraries available.
# pylint: disable=super-on-old-class
class MidonetPluginV2(plugin.MidonetMixin):

    vendor_extensions = plugin.MidonetMixin.supported_extension_aliases
    supported_extension_aliases = ['external-net', 'router', 'security-group',
                                   'agent', 'dhcp_agent_scheduler', 'binding',
                                   'quotas'] + vendor_extensions

    __native_bulk_support = True

    def __init__(self):
        super(MidonetPluginV2, self).__init__()
