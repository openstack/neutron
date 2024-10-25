#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.db import resource_extend


def _make_port_details_dict(port):
    return {'name': port['name'],
            'network_id': port['network_id'],
            'mac_address': port['mac_address'],
            'admin_state_up': port['admin_state_up'],
            'status': port['status'],
            'device_id': port['device_id'],
            'device_owner': port['device_owner']}


@resource_extend.has_resource_extenders
class Fip_port_details_db_mixin:
    """Mixin class to enable floating IP's port_details attributes."""

    @staticmethod
    @resource_extend.extends([l3_apidef.FLOATINGIPS])
    def _extend_fip_dict_device_id(fip_res, fip_db):
        if fip_db.fixed_port:
            fip_res['port_details'] = _make_port_details_dict(
                fip_db.fixed_port)
        else:
            fip_res['port_details'] = None
        return fip_res
