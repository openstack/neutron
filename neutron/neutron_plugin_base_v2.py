# Copyright 2011 VMware, Inc.
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

"""
v2 Neutron Plug-in API specification.

:class:`NeutronPluginBaseV2` provides the definition of minimum set of
methods that needs to be implemented by a v2 Neutron Plug-in.
"""

import abc

from neutron_lib.services import base as base_services
import six


@six.add_metaclass(abc.ABCMeta)
class NeutronPluginBaseV2(base_services.WorkerBase):

    @abc.abstractmethod
    def create_subnet(self, context, subnet):
        """Create a subnet.

        Create a subnet, which represents a range of IP addresses
        that can be allocated to devices

        :param context: neutron api request context
        :param subnet: dictionary describing the subnet, with keys
                       as listed in the  :obj:`RESOURCE_ATTRIBUTE_MAP` object
                       in :file:`neutron/api/v2/attributes.py`.  All keys will
                       be populated.
        """
        pass

    @abc.abstractmethod
    def update_subnet(self, context, id, subnet):
        """Update values of a subnet.

        :param context: neutron api request context
        :param id: UUID representing the subnet to update.
        :param subnet: dictionary with keys indicating fields to update.
                       valid keys are those that have a value of True for
                       'allow_put' as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`.
        """
        pass

    @abc.abstractmethod
    def get_subnet(self, context, id, fields=None):
        """Retrieve a subnet.

        :param context: neutron api request context
        :param id: UUID representing the subnet to fetch.
        :param fields: a list of strings that are valid keys in a
                       subnet dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`. Only these fields
                       will be returned.
        """
        pass

    @abc.abstractmethod
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        """Retrieve a list of subnets.

        The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a subnet as listed in the :obj:`RESOURCE_ATTRIBUTE_MAP`
                        object in :file:`neutron/api/v2/attributes.py`.
                        Values in this dictionary are an iterable containing
                        values that will be used for an exact match comparison
                        for that value.  Each result returned by this
                        function will have matched one of the values for each
                        key in filters.
        :param fields: a list of strings that are valid keys in a
                       subnet dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`. Only these fields
                       will be returned.
        """
        pass

    def get_subnets_count(self, context, filters=None):
        """Return the number of subnets.

        The result depends on the identity of
        the user making the request (as indicated by the context) as well as
        any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a network as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/api/v2/attributes.py`.  Values in this
                        dictionary are an iterable containing values that
                        will be used for an exact match comparison for that
                        value.  Each result returned by this function will
                        have matched one of the values for each key in filters.

        .. note:: this method is optional, as it was not part of the originally
                  defined plugin API.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_subnet(self, context, id):
        """Delete a subnet.

        :param context: neutron api request context
        :param id: UUID representing the subnet to delete.
        """
        pass

    def create_subnetpool(self, context, subnetpool):
        """Create a subnet pool.

        :param context: neutron api request context
        :param subnetpool: Dictionary representing the subnetpool to create.
        """
        raise NotImplementedError()

    def update_subnetpool(self, context, id, subnetpool):
        """Update a subnet pool.

        :param context: neutron api request context
        :param subnetpool: Dictionary representing the subnetpool attributes
                           to update.
        """
        raise NotImplementedError()

    def get_subnetpool(self, context, id, fields=None):
        """Show a subnet pool.

        :param context: neutron api request context
        :param id: The UUID of the subnetpool to show.
        """
        raise NotImplementedError()

    def get_subnetpools(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        """Retrieve list of subnet pools."""
        raise NotImplementedError()

    def delete_subnetpool(self, context, id):
        """Delete a subnet pool.

        :param context: neutron api request context
        :param id: The UUID of the subnet pool to delete.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def create_network(self, context, network):
        """Create a network.

        Create a network, which represents an L2 network segment which
        can have a set of subnets and ports associated with it.

        :param context: neutron api request context
        :param network: dictionary describing the network, with keys
                        as listed in the  :obj:`RESOURCE_ATTRIBUTE_MAP` object
                        in :file:`neutron/api/v2/attributes.py`.  All keys will
                        be populated.

        """
        pass

    @abc.abstractmethod
    def update_network(self, context, id, network):
        """Update values of a network.

        :param context: neutron api request context
        :param id: UUID representing the network to update.
        :param network: dictionary with keys indicating fields to update.
                        valid keys are those that have a value of True for
                        'allow_put' as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/api/v2/attributes.py`.
        """
        pass

    @abc.abstractmethod
    def get_network(self, context, id, fields=None):
        """Retrieve a network.

        :param context: neutron api request context
        :param id: UUID representing the network to fetch.
        :param fields: a list of strings that are valid keys in a
                       network dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`. Only these fields
                       will be returned.
        """
        pass

    @abc.abstractmethod
    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        """Retrieve a list of networks.

        The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a network as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/api/v2/attributes.py`.  Values in this
                        dictionary are an iterable containing values that will
                        be used for an exact match comparison for that value.
                        Each result returned by this function will have matched
                        one of the values for each key in filters.
        :param fields: a list of strings that are valid keys in a
                       network dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`. Only these fields
                       will be returned.
        """
        pass

    def get_networks_count(self, context, filters=None):
        """Return the number of networks.

        The result depends on the identity
        of the user making the request (as indicated by the context) as well
        as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a network as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object
                        in :file:`neutron/api/v2/attributes.py`. Values in
                        this dictionary are an iterable containing values that
                        will be used for an exact match comparison for that
                        value.  Each result returned by this function will have
                        matched one of the values for each key in filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_network(self, context, id):
        """Delete a network.

        :param context: neutron api request context
        :param id: UUID representing the network to delete.
        """
        pass

    @abc.abstractmethod
    def create_port(self, context, port):
        """Create a port.

        Create a port, which is a connection point of a device (e.g., a VM
        NIC) to attach to a L2 neutron network.

        :param context: neutron api request context
        :param port: dictionary describing the port, with keys as listed in the
                     :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                     :file:`neutron/api/v2/attributes.py`.  All keys will be
                     populated.
        """
        pass

    @abc.abstractmethod
    def update_port(self, context, id, port):
        """Update values of a port.

        :param context: neutron api request context
        :param id: UUID representing the port to update.
        :param port: dictionary with keys indicating fields to update.
                     valid keys are those that have a value of True for
                     'allow_put' as listed in the :obj:`RESOURCE_ATTRIBUTE_MAP`
                     object in :file:`neutron/api/v2/attributes.py`.
        """
        pass

    @abc.abstractmethod
    def get_port(self, context, id, fields=None):
        """Retrieve a port.

        :param context: neutron api request context
        :param id: UUID representing the port to fetch.
        :param fields: a list of strings that are valid keys in a port
                       dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`. Only these fields
                       will be returned.
        """
        pass

    @abc.abstractmethod
    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None, page_reverse=False):
        """Retrieve a list of ports.

        The contents of the list depends on the identity of the user making
        the request (as indicated by the context) as well as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a port as listed in the  :obj:`RESOURCE_ATTRIBUTE_MAP`
                        object in :file:`neutron/api/v2/attributes.py`. Values
                        in this dictionary are an iterable containing values
                        that will be used for an exact match comparison for
                        that value.  Each result returned by this function will
                        have matched one of the values for each key in filters.
        :param fields: a list of strings that are valid keys in a
                       port dictionary as listed in the
                       :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                       :file:`neutron/api/v2/attributes.py`. Only these fields
                       will be returned.
        """
        pass

    def get_ports_count(self, context, filters=None):
        """Return the number of ports.

        The result depends on the identity of the user making the request
        (as indicated by the context) as well as any filters.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for
                        a network as listed in the
                        :obj:`RESOURCE_ATTRIBUTE_MAP` object in
                        :file:`neutron/api/v2/attributes.py`.  Values in this
                        dictionary are an iterable containing values that will
                        be used for an exact match comparison for that value.
                        Each result returned by this function will have matched
                        one of the values for each key in filters.

        .. note:: this method is optional, as it was not part of the originally
                  defined plugin API.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_port(self, context, id):
        """Delete a port.

        :param context: neutron api request context
        :param id: UUID representing the port to delete.
        """
        pass

    def start_rpc_listeners(self):
        """Start the RPC listeners.

        Most plugins start RPC listeners implicitly on initialization.  In
        order to support multiple process RPC, the plugin needs to expose
        control over when this is started.

        .. note:: this method is optional, as it was not part of the originally
                  defined plugin API.
        """
        raise NotImplementedError()

    def start_rpc_state_reports_listener(self):
        """Start the RPC listeners consuming state reports queue.

        This optional method creates rpc consumer for REPORTS queue only.

        .. note:: this method is optional, as it was not part of the originally
                  defined plugin API.
        """
        raise NotImplementedError()

    def rpc_workers_supported(self):
        """Return whether the plugin supports multiple RPC workers.

        A plugin that supports multiple RPC workers should override the
        start_rpc_listeners method to ensure that this method returns True and
        that start_rpc_listeners is called at the appropriate time.
        Alternately, a plugin can override this method to customize detection
        of support for multiple rpc workers

        .. note:: this method is optional, as it was not part of the originally
                  defined plugin API.
        """
        return (self.__class__.start_rpc_listeners !=
                NeutronPluginBaseV2.start_rpc_listeners)

    def rpc_state_report_workers_supported(self):
        """Return whether the plugin supports state report RPC workers.

        .. note:: this method is optional, as it was not part of the originally
                  defined plugin API.
        """
        return (self.__class__.start_rpc_state_reports_listener !=
                NeutronPluginBaseV2.start_rpc_state_reports_listener)

    def has_native_datastore(self):
        """Return True if the plugin uses Neutron's native datastore.

        .. note:: plugins like ML2 should override this method and return True.
        """
        return False
