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

from neutron.services.evpn import constants as evpn_const


def evpn_ls_name(vni):
    return '%s%s' % (evpn_const.EVPN_LS_NAME_PREFIX, vni)


def evpn_lrp_name(router_id, vni):
    return evpn_const.EVPN_LRP_NAME_PATTERN % {
        'lrp_uuid': router_id[:12],
        'evpn_ls_name': evpn_ls_name(vni),
    }


def evpn_lsp_name(router_id, vni):
    return evpn_const.EVPN_LSP_NAME_PATTERN % {
        'evpn_ls_name': evpn_ls_name(vni),
        'lrp_uuid': router_id[:12],
    }


def evpn_hcg_name(router_id):
    return '%s%s' % (evpn_const.EVPN_HCG_NAME_PREFIX, router_id)
