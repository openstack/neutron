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

EXPERIMENTAL_CFG_GROUP = 'experimental'
EXPERIMENTAL_LINUXBRIDGE = 'linuxbridge'
experimental_opts = [
    cfg.BoolOpt(EXPERIMENTAL_LINUXBRIDGE,
                default=False,
                help=_('Enable execution of the experimental Linuxbridge '
                       'agent.')),
]


def register_experimental_opts(cfg=cfg.CONF):
    cfg.register_opts(experimental_opts, EXPERIMENTAL_CFG_GROUP)
