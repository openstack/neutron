# Copyright 2012 NEC Corporation.  All rights reserved.
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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class OFCDriverBase(object):
    """OpenFlow Controller (OFC) Driver Specification.

    OFCDriverBase defines the minimum set of methods required by this plugin.
    It would be better that other methods like update_* are implemented.
    """

    @abc.abstractmethod
    def create_tenant(self, description, tenant_id=None):
        """Create a new tenant at OpenFlow Controller.

        :param description: A description of this tenant.
        :param tenant_id: A hint of OFC tenant ID.
                          A driver could use this id as a OFC id or ignore it.
        :returns: ID of the tenant created at OpenFlow Controller.
        :raises: neutron.plugin.nec.common.exceptions.OFCException
        """
        pass

    @abc.abstractmethod
    def delete_tenant(self, ofc_tenant_id):
        """Delete a tenant at OpenFlow Controller.

        :raises: neutron.plugin.nec.common.exceptions.OFCException
        """
        pass

    @abc.abstractmethod
    def create_network(self, ofc_tenant_id, description, network_id=None):
        """Create a new network on specified OFC tenant at OpenFlow Controller.

        :param ofc_tenant_id: a OFC tenant ID in which a new network belongs.
        :param description: A description of this network.
        :param network_id: A hint of an ID of OFC network.
        :returns: ID of the network created at OpenFlow Controller.
            ID returned must be unique in the OpenFlow Controller.
            If a network is identified in conjunction with other information
            such as a tenant ID, such information should be included in the ID.
        :raises: neutron.plugin.nec.common.exceptions.OFCException
        """
        pass

    @abc.abstractmethod
    def delete_network(self, ofc_network_id):
        """Delete a netwrok at OpenFlow Controller.

        :raises: neutron.plugin.nec.common.exceptions.OFCException
        """
        pass

    @abc.abstractmethod
    def create_port(self, ofc_network_id, portinfo,
                    port_id=None, filters=None):
        """Create a new port on specified network at OFC.

        :param ofc_network_id: a OFC tenant ID in which a new port belongs.
        :param portinfo: An OpenFlow information of this port.
                    {'datapath_id': Switch ID that a port connected.
                     'port_no': Port Number that a port connected on a Swtich.
                     'vlan_id': VLAN ID that a port tagging.
                     'mac': Mac address.
                    }
        :param port_id: A hint of an ID of OFC port.
            ID returned must be unique in the OpenFlow Controller.

            If a port is identified in combination with a network or
            a tenant, such information should be included in the ID.
        :param filters: A list of packet filter associated with the port.
            Each element is a tuple (neutron ID, OFC ID)

        :returns: ID of the port created at OpenFlow Controller.
        :raises: neutron.plugin.nec.common.exceptions.OFCException
        """
        pass

    @abc.abstractmethod
    def delete_port(self, ofc_port_id):
        """Delete a port at OpenFlow Controller.

        :raises: neutron.plugin.nec.common.exceptions.OFCException
        """
        pass
