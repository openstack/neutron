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


ROUTER_DISTRIBUTED_OPTS = [
    cfg.BoolOpt('router_distributed',
                default=False,
                help=_("System-wide flag to determine the type of router "
                       "that tenants can create. Only admin can override.")),
    cfg.BoolOpt('enable_dvr',
                default=True,
                help=_("Determine if setup is configured for DVR. If False, "
                       "DVR API extension will be disabled.")),
]


def register_db_l3_dvr_opts(conf=cfg.CONF):
    conf.register_opts(ROUTER_DISTRIBUTED_OPTS)
