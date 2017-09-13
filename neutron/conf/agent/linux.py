# Copyright 2017 OpenStack Foundation
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

from neutron._i18n import _

from oslo_config import cfg

IP_LIB_OPTS_LINUX = [
    cfg.BoolOpt('ip_lib_force_root',
                default=False,
                help=_('Force ip_lib calls to use the root helper')),
]


def register_iplib_opts(cfg=cfg.CONF):
    cfg.register_opts(IP_LIB_OPTS_LINUX)
