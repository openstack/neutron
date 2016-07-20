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


DVR_MAC_ADDRESS_OPTS = [
    cfg.StrOpt('dvr_base_mac',
               default="fa:16:3f:00:00:00",
               help=_("The base mac address used for unique "
                      "DVR instances by Neutron. The first 3 octets will "
                      "remain unchanged. If the 4th octet is not 00, it will "
                      "also be used. The others will be randomly generated. "
                      "The 'dvr_base_mac' *must* be different from "
                      "'base_mac' to avoid mixing them up with MAC's "
                      "allocated for tenant ports. A 4 octet example would be "
                      "dvr_base_mac = fa:16:3f:4f:00:00. The default is 3 "
                      "octet")),
]


def register_db_dvr_mac_opts(conf=cfg.CONF):
    conf.register_opts(DVR_MAC_ADDRESS_OPTS)
