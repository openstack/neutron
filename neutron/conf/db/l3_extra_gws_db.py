# Copyright (c) 2023 Canonical Ltd.
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


L3_EXTRA_GWS_OPTS = [
    cfg.BoolOpt('enable_default_route_ecmp',
                default=False,
                help=_("Define the default value for "
                       "enable_default_route_ecmp if not specified on the "
                       "router.")),
    cfg.BoolOpt('enable_default_route_bfd',
                default=False,
                help=_("Define the default value for "
                       "enable_default_route_bfd if not specified on the "
                       "router.")),
]


def register_db_l3_extragws_opts(conf=cfg.CONF):
    conf.register_opts(L3_EXTRA_GWS_OPTS)
