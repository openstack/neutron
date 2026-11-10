# Copyright 2026 OpenStack Foundation
#
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

TRUNK_GROUP = 'trunk'

trunk_opts = [
    cfg.IntOpt('max_subports_per_trunk',
               default=128,
               min=1,
               max=4094,
               help=_("Maximum number of subports allowed on a single "
                      "trunk. Mechanism drivers that program physical "
                      "switches may be unable to handle a large number of "
                      "VLANs per port, so operators can set a limit that "
                      "matches their hardware. Requests that would exceed "
                      "the limit are rejected.")),
]


def register_trunk_opts(conf=cfg.CONF):
    conf.register_opts(trunk_opts, group=TRUNK_GROUP)
