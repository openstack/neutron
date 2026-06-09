# Copyright 2026 Red Hat, LLC
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

EVPN_LRP_VNI_EXT_ID_KEY = 'vni'
EVPN_LRP_VLAN_EXT_ID_KEY = 'vlan'
EVPN_LS_NAME_PREFIX = 'evpn-ls-'
EVPN_LRP_NAME_PATTERN = 'evpn-lrp-%(lrp_uuid)s-to-%(evpn_ls_name)s'
EVPN_LSP_NAME_PATTERN = 'evpn-lsp-%(evpn_ls_name)s-to-%(lrp_uuid)s'
EVPN_HCG_NAME_PREFIX = 'evpn-hcg-'
