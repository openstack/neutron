# Copyright (c) 2023 Red Hat, Inc.
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

from neutron_lib.api.definitions import port_hardware_offload_type as phot
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const

from neutron.objects.port.extensions import port_hardware_offload_type as \
    phot_obj


class PortHardwareOffloadTypeDbMixin(object):
    """Mixin class to add hardware offload type extension to a port"""

    def _process_create_port(self, context, data, result):
        hw_type = data.get(phot.HARDWARE_OFFLOAD_TYPE)
        if hw_type not in n_const.VALID_HWOL_TYPES:
            result[phot.HARDWARE_OFFLOAD_TYPE] = None
            return

        obj = phot_obj.PortHardwareOffloadType(
            context, port_id=result['id'], hardware_offload_type=hw_type)
        obj.create()
        result[phot.HARDWARE_OFFLOAD_TYPE] = hw_type
        # NOTE(ralonsoh): this is updating not the "result" dictionary but
        # the "data" dictionary that are the API input parameters.
        try:
            pb_profile = data[portbindings.PROFILE]
            capabilities = pb_profile.get('capabilities', [])
            if hw_type not in capabilities:
                capabilities.append(hw_type)
            data[portbindings.PROFILE]['capabilities'] = capabilities
        except (AttributeError, KeyError):
            data[portbindings.PROFILE] = {'capabilities': [hw_type]}

    def _extend_port_dict(self, port_db, result):
        if port_db.hardware_offload_type:
            result[phot.HARDWARE_OFFLOAD_TYPE] = (
                port_db.hardware_offload_type.hardware_offload_type)
        else:
            result[phot.HARDWARE_OFFLOAD_TYPE] = None
