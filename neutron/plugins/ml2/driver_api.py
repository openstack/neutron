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

import abc
import six

# The following keys are used in the segment dictionaries passed via
# the driver API. These are defined separately from similar keys in
# neutron.extensions.providernet so that drivers don't need to change
# if/when providernet moves to the core API.
#
ID = 'id'
NETWORK_TYPE = 'network_type'
PHYSICAL_NETWORK = 'physical_network'
SEGMENTATION_ID = 'segmentation_id'


@six.add_metaclass(abc.ABCMeta)
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

    @abc.abstractmethod
    def get_type(self):
        """Get driver's network type.

        :returns network_type value handled by this driver
        """
        pass

    @abc.abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    @abc.abstractmethod
    def is_partial_segment(self, segment):
        """Return True if segment is a partially specified segment.

        :param segment: segment dictionary
        :returns: boolean
        """

    @abc.abstractmethod
    def validate_provider_segment(self, segment):
        """Validate attributes of a provider network segment.

        :param segment: segment dictionary using keys defined above
        :raises: neutron.common.exceptions.InvalidInput if invalid

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

    @abc.abstractmethod
    def reserve_provider_segment(self, session, segment):
        """Reserve resource associated with a provider network segment.

        :param session: database session
        :param segment: segment dictionary
        :returns: segment dictionary

        Called inside transaction context on session to reserve the
        type-specific resource for a provider network segment. The
        segment dictionary passed in was returned by a previous
        validate_provider_segment() call.
        """
        pass

    @abc.abstractmethod
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

    @abc.abstractmethod
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


@six.add_metaclass(abc.ABCMeta)
class NetworkContext(object):
    """Context passed to MechanismDrivers for changes to network resources.

    A NetworkContext instance wraps a network resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached so that other
    MechanismDrivers can freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the network in its current configuration.

        Return the network, as defined by NeutronPluginBaseV2.
        create_network and all extensions in the ml2 plugin, with
        all its properties 'current' at the time the context was
        established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the network in its original configuration.

        Return the network, with all its properties set to their
        original values prior to a call to update_network. Method is
        only valid within calls to update_network_precommit and
        update_network_postcommit.
        """
        pass

    @abc.abstractproperty
    def network_segments(self):
        """Return the segments associated with this network resource."""
        pass


@six.add_metaclass(abc.ABCMeta)
class SubnetContext(object):
    """Context passed to MechanismDrivers for changes to subnet resources.

    A SubnetContext instance wraps a subnet resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached so that other
    MechanismDrivers can freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the subnet in its current configuration.

        Return the subnet, as defined by NeutronPluginBaseV2.
        create_subnet and all extensions in the ml2 plugin, with
        all its properties 'current' at the time the context was
        established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the subnet in its original configuration.

        Return the subnet, with all its properties set to their
        original values prior to a call to update_subnet. Method is
        only valid within calls to update_subnet_precommit and
        update_subnet_postcommit.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class PortContext(object):
    """Context passed to MechanismDrivers for changes to port resources.

    A PortContext instance wraps a port resource. It provides helper
    methods for accessing other relevant information. Results from
    expensive operations are cached so that other MechanismDrivers can
    freely access the same information.
    """

    @abc.abstractproperty
    def current(self):
        """Return the port in its current configuration.

        Return the port, as defined by NeutronPluginBaseV2.
        create_port and all extensions in the ml2 plugin, with
        all its properties 'current' at the time the context was
        established.
        """
        pass

    @abc.abstractproperty
    def original(self):
        """Return the port in its original configuration.

        Return the port, with all its properties set to their
        original values prior to a call to update_port. Method is
        only valid within calls to update_port_precommit and
        update_port_postcommit.
        """
        pass

    @abc.abstractproperty
    def status(self):
        """Return the status of the current port."""
        pass

    @abc.abstractproperty
    def original_status(self):
        """Return the status of the original port.

        The method is only valid within calls to update_port_precommit and
        update_port_postcommit.
        """
        pass

    @abc.abstractproperty
    def network(self):
        """Return the NetworkContext associated with this port."""
        pass

    @abc.abstractproperty
    def bound_segment(self):
        """Return the currently bound segment dictionary."""
        pass

    @abc.abstractproperty
    def original_bound_segment(self):
        """Return the original bound segment dictionary.

        Return the original bound segment dictionary, prior to a call
        to update_port.  Method is only valid within calls to
        update_port_precommit and update_port_postcommit.
        """
        pass

    @abc.abstractproperty
    def host(self):
        """Return the host associated with the 'current' port."""
        pass

    @abc.abstractproperty
    def original_host(self):
        """Return the host associated with the 'original' port.

        Method is only valid within calls to update_port_precommit
        and update_port_postcommit.
        """
        pass

    @abc.abstractproperty
    def bound_driver(self):
        """Return the currently bound mechanism driver name."""
        pass

    @abc.abstractproperty
    def original_bound_driver(self):
        """Return the original bound mechanism driver name.

        Return the original bound mechanism driver name, prior to a
        call to update_port.  Method is only valid within calls to
        update_port_precommit and update_port_postcommit.
        """
        pass

    @abc.abstractmethod
    def host_agents(self, agent_type):
        """Get agents of the specified type on port's host.

        :param agent_type: Agent type identifier
        :returns: List of agents_db.Agent records
        """
        pass

    @abc.abstractmethod
    def set_binding(self, segment_id, vif_type, vif_details,
                    status=None):
        """Set the binding for the port.

        :param segment_id: Network segment bound for the port.
        :param vif_type: The VIF type for the bound port.
        :param vif_details: Dictionary with details for VIF driver.
        :param status: Port status to set if not None.

        Called by MechanismDriver.bind_port to indicate success and
        specify binding details to use for port. The segment_id must
        identify an item in network.network_segments.
        """
        pass

    @abc.abstractmethod
    def allocate_dynamic_segment(self, segment):
        """Allocate a dynamic segment.

        :param segment: A partially or fully specified segment dictionary

        Called by the MechanismDriver.bind_port, create_port or update_port
        to dynamically allocate a segment for the port using the partial
        segment specified. The segment dictionary can be a fully or partially
        specified segment. At a minumim it needs the network_type populated to
        call on the appropriate type driver.
        """
        pass

    @abc.abstractmethod
    def release_dynamic_segment(self, segment_id):
        """Release an allocated dynamic segment.

        :param segment_id: UUID of the dynamic network segment.

        Called by the MechanismDriver.delete_port or update_port to release
        the dynamic segment allocated for this port.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class MechanismDriver(object):
    """Define stable abstract interface for ML2 mechanism drivers.

    A mechanism driver is called on the creation, update, and deletion
    of networks and ports. For every event, there are two methods that
    get called - one within the database transaction (method suffix of
    _precommit), one right afterwards (method suffix of _postcommit).

    Exceptions raised by methods called inside the transaction can
    rollback, but should not make any blocking calls (for example,
    REST requests to an outside controller). Methods called after
    transaction commits can make blocking external calls, though these
    will block the entire process. Exceptions raised in calls after
    the transaction commits may cause the associated resource to be
    deleted.

    Because rollback outside of the transaction is not done in the
    update network/port case, all data validation must be done within
    methods that are part of the database transaction.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    def create_network_precommit(self, context):
        """Allocate resources for a new network.

        :param context: NetworkContext instance describing the new
        network.

        Create a new network, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_network_postcommit(self, context):
        """Create a network.

        :param context: NetworkContext instance describing the new
        network.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_network_precommit(self, context):
        """Update resources of a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Update values of a network, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_network_precommit is called for all changes to the
        network state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_network_postcommit(self, context):
        """Update a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_network_postcommit is called for all changes to the
        network state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_network_precommit(self, context):
        """Delete resources for a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Delete network resources previously allocated by this
        mechanism driver for a network. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    def delete_network_postcommit(self, context):
        """Delete a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_subnet_precommit(self, context):
        """Allocate resources for a new subnet.

        :param context: SubnetContext instance describing the new
        subnet.

        Create a new subnet, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_subnet_postcommit(self, context):
        """Create a subnet.

        :param context: SubnetContext instance describing the new
        subnet.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_subnet_precommit(self, context):
        """Update resources of a subnet.

        :param context: SubnetContext instance describing the new
        state of the subnet, as well as the original state prior
        to the update_subnet call.

        Update values of a subnet, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_subnet_precommit is called for all changes to the
        subnet state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_subnet_postcommit(self, context):
        """Update a subnet.

        :param context: SubnetContext instance describing the new
        state of the subnet, as well as the original state prior
        to the update_subnet call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_subnet_postcommit is called for all changes to the
        subnet state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_subnet_precommit(self, context):
        """Delete resources for a subnet.

        :param context: SubnetContext instance describing the current
        state of the subnet, prior to the call to delete it.

        Delete subnet resources previously allocated by this
        mechanism driver for a subnet. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    def delete_subnet_postcommit(self, context):
        """Delete a subnet.

        :param context: SubnetContext instance describing the current
        state of the subnet, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_port_precommit(self, context):
        """Allocate resources for a new port.

        :param context: PortContext instance describing the port.

        Create a new port, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_port_postcommit(self, context):
        """Create a port.

        :param context: PortContext instance describing the port.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.
        """
        pass

    def update_port_precommit(self, context):
        """Update resources of a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called inside transaction context on session to complete a
        port update as defined by this mechanism driver. Raising an
        exception will result in rollback of the transaction.

        update_port_precommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
        pass

    def update_port_postcommit(self, context):
        """Update a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.

        update_port_postcommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
        pass

    def delete_port_precommit(self, context):
        """Delete resources of a port.

        :param context: PortContext instance describing the current
        state of the port, prior to the call to delete it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        pass

    def delete_port_postcommit(self, context):
        """Delete a port.

        :param context: PortContext instance describing the current
        state of the port, prior to the call to delete it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        Called outside any transaction to attempt to establish a port
        binding using this mechanism driver. If the driver is able to
        bind the port, it must call context.set_binding() with the
        binding details. If the binding results are committed after
        bind_port() returns, they will be seen by all mechanism
        drivers as update_port_precommit() and
        update_port_postcommit() calls.

        Note that if some other thread or process concurrently binds
        or updates the port, these binding results will not be
        committed, and update_port_precommit() and
        update_port_postcommit() will not be called on the mechanism
        drivers with these results. Because binding results can be
        discarded rather than committed, drivers should avoid making
        persistent state changes in bind_port(), or else must ensure
        that such state changes are eventually cleaned up.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ExtensionDriver(object):
    """Define stable abstract interface for ML2 extension drivers.

    An extension driver extends the core resources implemented by the
    ML2 plugin with additional attributes. Methods that process create
    and update operations for these resources validate and persist
    values for extended attributes supplied through the API. Other
    methods extend the resource dictionaries returned from the API
    operations with the values of the extended attributes.
    """

    @abc.abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    @abc.abstractproperty
    def extension_alias(self):
        """Supported extension alias.

        Return the alias identifying the core API extension supported
        by this driver.
        """
        pass

    def process_create_network(self, session, data, result):
        """Process extended attributes for create network.

        :param session: database session
        :param data: dictionary of incoming network data
        :param result: network dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended network attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_create_subnet(self, session, data, result):
        """Process extended attributes for create subnet.

        :param session: database session
        :param data: dictionary of incoming subnet data
        :param result: subnet dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended subnet attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_create_port(self, session, data, result):
        """Process extended attributes for create port.

        :param session: database session
        :param data: dictionary of incoming port data
        :param result: port dictionary to extend

        Called inside transaction context on session to validate and
        persist any extended port attributes defined by this
        driver. Extended attribute values must also be added to
        result.
        """
        pass

    def process_update_network(self, session, data, result):
        """Process extended attributes for update network.

        :param session: database session
        :param data: dictionary of incoming network data
        :param result: network dictionary to extend

        Called inside transaction context on session to validate and
        update any extended network attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def process_update_subnet(self, session, data, result):
        """Process extended attributes for update subnet.

        :param session: database session
        :param data: dictionary of incoming subnet data
        :param result: subnet dictionary to extend

        Called inside transaction context on session to validate and
        update any extended subnet attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def process_update_port(self, session, data, result):
        """Process extended attributes for update port.

        :param session: database session
        :param data: dictionary of incoming port data
        :param result: port dictionary to extend

        Called inside transaction context on session to validate and
        update any extended port attributes defined by this
        driver. Extended attribute values, whether updated or not,
        must also be added to result.
        """
        pass

    def extend_network_dict(self, session, result):
        """Add extended attributes to network dictionary.

        :param session: database session
        :param result: network dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a network
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a network operation.
        """
        pass

    def extend_subnet_dict(self, session, result):
        """Add extended attributes to subnet dictionary.

        :param session: database session
        :param result: subnet dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a subnet
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a subnet operation.
        """
        pass

    def extend_port_dict(self, session, result):
        """Add extended attributes to port dictionary.

        :param session: database session
        :param result: port dictionary to extend

        Called inside transaction context on session to add any
        extended attributes defined by this driver to a port
        dictionary to be used for mechanism driver calls and/or
        returned as the result of a port operation.
        """
        pass
