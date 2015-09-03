# Copyright 2013 VMware, Inc.  All rights reserved.
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
from neutron.db import db_base_plugin_v2
from neutron.db import portsecurity_db_common
from neutron.extensions import portsecurity as psec


class PortSecurityDbMixin(portsecurity_db_common.PortSecurityDbCommon):
    # Register dict extend functions for ports and networks
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attrs.NETWORKS, ['_extend_port_security_dict'])
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attrs.PORTS, ['_extend_port_security_dict'])

    def _extend_port_security_dict(self, response_data, db_data):
        if ('port-security' in
            getattr(self, 'supported_extension_aliases', [])):
            psec_value = db_data['port_security'][psec.PORTSECURITY]
            response_data[psec.PORTSECURITY] = psec_value

    def _determine_port_security_and_has_ip(self, context, port):
        """Returns a tuple of booleans (port_security_enabled, has_ip).

        Port_security is the value associated with the port if one is present
        otherwise the value associated with the network is returned. has_ip is
        if the port is associated with an ip or not.
        """
        has_ip = self._ip_on_port(port)
        # we don't apply security groups for dhcp, router
        if (port.get('device_owner') and
                port['device_owner'].startswith('network:')):
            return (False, has_ip)

        if attrs.is_attr_set(port.get(psec.PORTSECURITY)):
            port_security_enabled = port[psec.PORTSECURITY]

        # If port has an ip and security_groups are passed in
        # conveniently set port_security_enabled to true this way
        # user doesn't also have to pass in port_security_enabled=True
        # when creating ports.
        elif (has_ip and attrs.is_attr_set(port.get('security_groups'))):
            port_security_enabled = True
        else:
            port_security_enabled = self._get_network_security_binding(
                context, port['network_id'])

        return (port_security_enabled, has_ip)

    def _ip_on_port(self, port):
        return bool(port.get('fixed_ips'))
