# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock


def patch_fake_ryu_client():
    ryu_mod = mock.Mock()
    ryu_app_mod = ryu_mod.app
    ryu_app_client = ryu_app_mod.client
    conf_switch_key = ryu_app_mod.conf_switch_key
    conf_switch_key.OVSDB_ADDR = 'ovsdb_addr'
    conf_switch_key.OVS_TUNNEL_ADDR = 'ovs_tunnel_addr'
    rest_nw_id = ryu_app_mod.rest_nw_id
    rest_nw_id.NW_ID_EXTERNAL = '__NW_ID_EXTERNAL__'
    rest_nw_id.NW_ID_RESERVED = '__NW_ID_RESERVED__'
    rest_nw_id.NW_ID_VPORT_GRE = '__NW_ID_VPORT_GRE__'
    rest_nw_id.NW_ID_UNKNOWN = '__NW_ID_UNKNOWN__'
    rest_nw_id.RESERVED_NETWORK_IDS = [
        rest_nw_id.NW_ID_EXTERNAL,
        rest_nw_id.NW_ID_RESERVED,
        rest_nw_id.NW_ID_VPORT_GRE,
        rest_nw_id.NW_ID_UNKNOWN,
    ]
    return mock.patch.dict('sys.modules',
                           {'ryu': ryu_mod,
                            'ryu.app': ryu_app_mod,
                            'ryu.app.client': ryu_app_client,
                            'ryu.app.conf_switch_key': conf_switch_key,
                            'ryu.app.rest_nw_id': rest_nw_id})
