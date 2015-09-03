# Copyright 2015 Intel Corporation.
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

from neutron.api.v2 import attributes as attrs
from neutron.db import common_db_mixin
from neutron.db import portsecurity_db_common as ps_db_common
from neutron.extensions import portsecurity as psec
from neutron.i18n import _LI
from neutron.plugins.ml2 import driver_api as api
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class PortSecurityExtensionDriver(api.ExtensionDriver,
                                  ps_db_common.PortSecurityDbCommon,
                                  common_db_mixin.CommonDbMixin):
    _supported_extension_alias = 'port-security'

    def initialize(self):
        LOG.info(_LI("PortSecurityExtensionDriver initialization complete"))

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_network(self, context, data, result):
        # Create the network extension attributes.
        if psec.PORTSECURITY not in data:
            data[psec.PORTSECURITY] = (psec.EXTENDED_ATTRIBUTES_2_0['networks']
                                       [psec.PORTSECURITY]['default'])
        self._process_network_port_security_create(context, data, result)

    def process_update_network(self, context, data, result):
        # Update the network extension attributes.
        if psec.PORTSECURITY in data:
            self._process_network_port_security_update(context, data, result)

    def process_create_port(self, context, data, result):
        # Create the port extension attributes.
        data[psec.PORTSECURITY] = self._determine_port_security(context, data)
        self._process_port_port_security_create(context, data, result)

    def process_update_port(self, context, data, result):
        if psec.PORTSECURITY in data:
            self._process_port_port_security_update(
                context, data, result)

    def extend_network_dict(self, session, db_data, result):
        self._extend_port_security_dict(result, db_data)

    def extend_port_dict(self, session, db_data, result):
        self._extend_port_security_dict(result, db_data)

    def _extend_port_security_dict(self, response_data, db_data):
        if db_data.get('port_security') is None:
            response_data[psec.PORTSECURITY] = (
                psec.EXTENDED_ATTRIBUTES_2_0['networks']
                [psec.PORTSECURITY]['default'])
        else:
            response_data[psec.PORTSECURITY] = (
                                db_data['port_security'][psec.PORTSECURITY])

    def _determine_port_security(self, context, port):
        """Returns a boolean (port_security_enabled).

        Port_security is the value associated with the port if one is present
        otherwise the value associated with the network is returned.
        """
        # we don't apply security groups for dhcp, router
        if (port.get('device_owner') and
                port['device_owner'].startswith('network:')):
            return False

        if attrs.is_attr_set(port.get(psec.PORTSECURITY)):
            port_security_enabled = port[psec.PORTSECURITY]
        else:
            port_security_enabled = self._get_network_security_binding(
                context, port['network_id'])

        return port_security_enabled
