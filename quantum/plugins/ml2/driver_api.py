# Copyright (c) 2013 OpenStack Foundation
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

from abc import ABCMeta, abstractmethod

# The following keys are used in the segment dictionaries passed via
# the driver API. These are defined separately from similar keys in
# quantum.extensions.providernet so that drivers don't need to change
# if/when providernet moves to the core API.
#
NETWORK_TYPE = 'network_type'
PHYSICAL_NETWORK = 'physical_network'
SEGMENTATION_ID = 'segmentation_id'


class TypeDriver(object):
    """Define stable abstract interface for ML2 type drivers.

    ML2 type drivers each support a specific network_type for provider
    and/or tenant network segments. Type drivers must implement this
    abstract interface, which defines the API by which the plugin uses
    the driver to manage the persistent type-specific resource
    allocation state associated with network segments of that type.

    Network segments are represented by segment dictionaries using the
    NETWORK_TYPE, PHYSICAL_NETWORK, and SEGMENTATION_ID keys defined
    above, corresponding to the provider attributes.  Future revisions
    of the TypeDriver API may add additional segment dictionary
    keys. Attributes not applicable for a particular network_type may
    either be excluded or stored as None.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def get_type(self):
        """Get driver's network type.

        :returns network_type value handled by this driver
        """
        pass

    @abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    @abstractmethod
    def validate_provider_segment(self, segment):
        """Validate attributes of a provider network segment.

        :param segment: segment dictionary using keys defined above
        :returns: segment dictionary with any defaulted attributes added
        :raises: quantum.common.exceptions.InvalidInput if invalid

        Called outside transaction context to validate the provider
        attributes for a provider network segment. Raise InvalidInput
        if:

         - any required attribute is missing
         - any prohibited or unrecognized attribute is present
         - any attribute value is not valid

        The network_type attribute is present in segment, but
        need not be validated.
        """
        pass

    @abstractmethod
    def reserve_provider_segment(self, session, segment):
        """Reserve resource associated with a provider network segment.

        :param session: database session
        :param segment: segment dictionary using keys defined above

        Called inside transaction context on session to reserve the
        type-specific resource for a provider network segment. The
        segment dictionary passed in was returned by a previous
        validate_provider_segment() call.
        """
        pass

    @abstractmethod
    def allocate_tenant_segment(self, session):
        """Allocate resource for a new tenant network segment.

        :param session: database session
        :returns: segment dictionary using keys defined above

        Called inside transaction context on session to allocate a new
        tenant network, typically from a type-specific resource
        pool. If successful, return a segment dictionary describing
        the segment. If tenant network segment cannot be allocated
        (i.e. tenant networks not supported or resource pool is
        exhausted), return None.
        """
        pass

    @abstractmethod
    def release_segment(self, session, segment):
        """Release network segment.

        :param session: database session
        :param segment: segment dictionary using keys defined above

        Called inside transaction context on session to release a
        tenant or provider network's type-specific resource. Runtime
        errors are not expected, but raising an exception will result
        in rollback of the transaction.
        """
        pass


class MechanismDriver(object):
    """Define stable abstract interface for ML2 mechanism drivers.

    Note that this is currently a stub class, but it is expected to be
    functional for the H-2 milestone. It currently serves mainly to
    help solidify the architectural distinction between TypeDrivers
    and MechanismDrivers.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    # TODO(rkukura): Add methods called inside and after transaction
    # for create_network, update_network, delete_network, create_port,
    # update_port, delete_port, and maybe for port binding
    # changes. Exceptions raised by methods called inside transactions
    # can rollback, but shouldn't block. Methods called after
    # transaction commits can block, and exceptions may cause deletion
    # of resource.
