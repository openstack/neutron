# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
class PluginSidePluggingDriver(object):
    """This class defines the API for plugging drivers.

    These are used used by Cisco (routing service) plugin to perform
    various operations on the logical ports of logical (service) resources
    in a plugin compatible way.
    """

    @abc.abstractmethod
    def create_hosting_device_resources(self, context, complementary_id,
                                        tenant_id, mgmt_nw_id,
                                        mgmt_sec_grp_id, max_hosted):
        """Create resources for a hosting device in a plugin specific way.

        Called when a hosting device is to be created so resources like
        networks and ports can be created for it in a plugin compatible
        way. This is primarily useful to service VMs.

        returns: a dict {'mgmt_port': <mgmt port or None>,
                         'ports': <list of ports>,
                         ... arbitrary driver items }

        :param context: Neutron api request context.
        :param complementary_id: complementary id of hosting device
        :param tenant_id: id of tenant owning the hosting device resources.
        :param mgmt_nw_id: id of management network for hosting devices.
        :param mgmt_sec_grp_id: id of security group for management network.
        :param max_hosted: maximum number of logical resources.
        """
        pass

    @abc.abstractmethod
    def get_hosting_device_resources(self, context, id, complementary_id,
                                     tenant_id, mgmt_nw_id):
        """Returns information about all resources for a hosting device.

        Called just before a hosting device is to be deleted so that
        information about the resources the hosting device uses can be
        collected.

        returns: a dict {'mgmt_port': <mgmt port or None>,
                         'ports': <list of ports>,
                         ... arbitrary driver items }

        :param context: Neutron api request context.
        :param id: id of hosting device.
        :param complementary_id: complementary id of hosting device
        :param tenant_id: id of tenant owning the hosting device resources.
        :param mgmt_nw_id: id of management network for hosting devices.
        """
        pass

    @abc.abstractmethod
    def delete_hosting_device_resources(self, context, tenant_id, mgmt_port,
                                        **kwargs):
        """Deletes resources for a hosting device in a plugin specific way.

        Called when a hosting device has been deleted (or when its creation
        has failed) so resources like networks and ports can be deleted in
        a plugin compatible way. This it primarily useful to service VMs.

        :param context: Neutron api request context.
        :param tenant_id: id of tenant owning the hosting device resources.
        :param mgmt_port: id of management port for the hosting device.
        :param kwargs: dictionary for any driver specific parameters.
        """
        pass

    @abc.abstractmethod
    def setup_logical_port_connectivity(self, context, port_db):
        """Establishes connectivity for a logical port.

        Performs the configuration tasks needed in the infrastructure
        to establish connectivity for a logical port.

        :param context: Neutron api request context.
        :param port_db: Neutron port that has been created.
        """
        pass

    @abc.abstractmethod
    def teardown_logical_port_connectivity(self, context, port_db):
        """Removes connectivity for a logical port.

        Performs the configuration tasks needed in the infrastructure
        to disconnect a logical port.

        Example: Remove a VLAN that is trunked to a service VM.

        :param context: Neutron api request context.
        :param port_db: Neutron port about to be deleted.
        """
        pass

    @abc.abstractmethod
    def extend_hosting_port_info(self, context, port_db, hosting_info):
        """Extends hosting information for a logical port.

        Allows a driver to add driver specific information to the
        hosting information for a logical port.

        :param context: Neutron api request context.
        :param port_db: Neutron port that hosting information concerns.
        :param hosting_info: dict with hosting port information to be extended.
        """
        pass

    @abc.abstractmethod
    def allocate_hosting_port(self, context, router_id, port_db, network_type,
                              hosting_device_id):
        """Allocates a hosting port for a logical port.

        Schedules a logical port to a hosting port. Note that the hosting port
        may be the logical port itself.

        returns: a dict {'allocated_port_id': <id of allocated port>,
                         'allocated_vlan': <allocated VLAN or None>} or
                 None if allocation failed

        :param context: Neutron api request context.
        :param router_id: id of Neutron router the logical port belongs to.
        :param port_db: Neutron logical router port.
        :param network_type: Type of network for logical router port
        :param hosting_device_id: id of hosting device
        """
        pass
