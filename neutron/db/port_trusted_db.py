# Copyright (c) 2024 Red Hat, Inc.
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

from neutron_lib.api.definitions import port_trusted_vif
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const

from neutron.objects.port.extensions import port_trusted as trusted_obj


class PortTrustedDbMixin:
    """Mixin class to add trusted extension to a port"""

    @staticmethod
    def _set_portbinding_profile(data, trusted):
        try:
            data[portbindings.PROFILE]['trusted'] = trusted
        except (AttributeError, KeyError):
            data[portbindings.PROFILE] = {'trusted': trusted}

    def _process_create_port(self, context, data, result):
        trusted = data.get(port_trusted_vif.TRUSTED_VIF)
        if trusted is n_const.ATTR_NOT_SPECIFIED:
            result[port_trusted_vif.TRUSTED_VIF] = None
            return

        obj = trusted_obj.PortTrusted(
            context, port_id=result['id'], trusted=trusted)
        obj.create()
        result[port_trusted_vif.TRUSTED_VIF] = trusted
        self._set_portbinding_profile(result, trusted)

    def _process_update_port(self, context, data, result):
        trusted = data.get(port_trusted_vif.TRUSTED_VIF)
        if trusted is None or trusted is n_const.ATTR_NOT_SPECIFIED:
            result[port_trusted_vif.TRUSTED_VIF] = None
            return

        obj = trusted_obj.PortTrusted.get_object(
            context, port_id=result['id'])
        if obj:
            obj.trusted = trusted
            obj.update()
            result[port_trusted_vif.TRUSTED_VIF] = trusted
            self._set_portbinding_profile(result, trusted)
        else:
            self._process_create_port(context, data, result)

    def _extend_port_dict(self, response_data, db_data):
        if db_data.trusted is not None:
            trusted = db_data.trusted.trusted
            response_data[port_trusted_vif.TRUSTED_VIF] = trusted
            self._set_portbinding_profile(response_data, trusted)
        else:
            response_data[port_trusted_vif.TRUSTED_VIF] = None
