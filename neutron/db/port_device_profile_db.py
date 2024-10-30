# Copyright (c) 2020 Red Hat, Inc.
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

from neutron_lib.api.definitions import port_device_profile as pdp

from neutron.objects.port.extensions import port_device_profile as pdp_obj


class PortDeviceProfileMixin:
    """Mixin class to add device profile (Cyborg) to a port"""

    def _process_create_port(self, context, data, result):
        if not data.get(pdp.DEVICE_PROFILE):
            result[pdp.DEVICE_PROFILE] = None
            return

        obj = pdp_obj.PortDeviceProfile(
            context, port_id=result['id'],
            device_profile=data[pdp.DEVICE_PROFILE])
        obj.create()
        result[pdp.DEVICE_PROFILE] = data[pdp.DEVICE_PROFILE]

    def _extend_port_dict(self, port_db, result):
        if port_db.device_profile:
            result[pdp.DEVICE_PROFILE] = port_db.device_profile.device_profile
        else:
            result[pdp.DEVICE_PROFILE] = None
