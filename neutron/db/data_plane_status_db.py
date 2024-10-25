# Copyright (c) 2017 NEC Corporation.  All rights reserved.
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

from neutron_lib.api.definitions import data_plane_status as dps_lib

from neutron.objects.port.extensions import data_plane_status as dps_obj


class DataPlaneStatusMixin:
    """Mixin class to add data plane status to a port"""

    def _process_create_port_data_plane_status(self, context, data, res):
        obj = dps_obj.PortDataPlaneStatus(
            context, port_id=res['id'],
            data_plane_status=data[dps_lib.DATA_PLANE_STATUS])
        obj.create()
        res[dps_lib.DATA_PLANE_STATUS] = data[dps_lib.DATA_PLANE_STATUS]

    def _process_update_port_data_plane_status(self, context, data,
                                               res):
        if dps_lib.DATA_PLANE_STATUS not in data:
            return

        obj = dps_obj.PortDataPlaneStatus.get_object(context,
                                                     port_id=res['id'])
        if obj:
            obj.data_plane_status = data[dps_lib.DATA_PLANE_STATUS]
            obj.update()
            res[dps_lib.DATA_PLANE_STATUS] = data[dps_lib.DATA_PLANE_STATUS]
        else:
            self._process_create_port_data_plane_status(context, data, res)

    @staticmethod
    def _extend_port_data_plane_status(port_res, port_db):
        port_res[dps_lib.DATA_PLANE_STATUS] = None

        if port_db.get(dps_lib.DATA_PLANE_STATUS):
            port_res[dps_lib.DATA_PLANE_STATUS] = (
                port_db[dps_lib.DATA_PLANE_STATUS].data_plane_status)
