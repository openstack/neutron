# Copyright 2023 SAP SE
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


OWNER_CHECK_OPTS = [
    cfg.IntOpt('owner_check_cache_expiration_time',
               default=5,
               min=1,
               help=_("Seconds to cache the OwnerCheck object field lookup, "
                      "e.g. Network.tenant_id. Only increase this far out for "
                      "static values like on Network.")),
]


def register_owner_check_opts(cfg=cfg.CONF):
    cfg.register_opts(OWNER_CHECK_OPTS)
