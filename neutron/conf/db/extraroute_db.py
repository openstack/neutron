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


EXTRA_ROUTE_OPTS = [
    cfg.IntOpt('max_routes',
               default=30,
               min=1,
               deprecated_for_removal=True,
               deprecated_since='2026.2',
               deprecated_reason=_(
                   'This per-router limit is replaced by the '
                   '"quota_router_route" quota in the '
                   '[QUOTAS] section.'),
               help=_("Maximum number of routes per router")),
]


def register_db_extraroute_opts(conf=cfg.CONF):
    conf.register_opts(EXTRA_ROUTE_OPTS)
