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

from neutron_lib.api.definitions import uplink_status_propagation as usp

from neutron.objects.port.extensions import uplink_status_propagation as \
    usp_obj


class UplinkStatusPropagationMixin(object):
    """Mixin class to add uplink propagation to a port"""

    def _process_create_port(self, context, data, res):
        obj = usp_obj.PortUplinkStatusPropagation(
            context, port_id=res['id'],
            propagate_uplink_status=data[usp.PROPAGATE_UPLINK_STATUS])
        obj.create()
        res[usp.PROPAGATE_UPLINK_STATUS] = data[usp.PROPAGATE_UPLINK_STATUS]

    @staticmethod
    def _extend_port_dict(port_res, port_db):
        # NOTE(ralonsoh): the default value is "True". Ports created before
        # enabling this extension won't have an associated
        # "PortUplinkStatusPropagation" register but we assume they have this
        # flag enabled.
        usp_db = port_db.get(usp.PROPAGATE_UPLINK_STATUS)
        port_res[usp.PROPAGATE_UPLINK_STATUS] = (
            usp_db.propagate_uplink_status if usp_db else True)
