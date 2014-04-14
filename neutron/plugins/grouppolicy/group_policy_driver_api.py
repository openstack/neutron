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

from abc import ABCMeta, abstractmethod, abstractproperty

import six


@six.add_metaclass(ABCMeta)
class EndpointContext(object):
    """Context passed to policy engine for changes to endpoint resources.

    An EndpointContext instance wraps an endpoint resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abstractproperty
    def current(self):
        """Return the current state of the endpoint.

        Return the current state of the endpoint, as defined by
        GroupPolicyPlugin.create_endpoint.
        """
        pass

    @abstractproperty
    def original(self):
        """Return the original state of the endpoint.

        Return the original state of the endpoint, prior to a call to
        update_endpoint. Method is only valid within calls to
        update_endpoint_precommit and update_endpoint_postcommit.
        """
        pass


@six.add_metaclass(ABCMeta)
class EndpointGroupContext(object):
    """Context passed to policy engine for changes to endpoint_group resources.

    An EndpointContext instance wraps an endpoint_group resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached for convenient access.
    """

    @abstractproperty
    def current(self):
        """Return the current state of the endpoint_group.

        Return the current state of the endpoint_group, as defined by
        GroupPolicyPlugin.create_endpoint_group.
        """
        pass

    @abstractproperty
    def original(self):
        """Return the original state of the endpoint_group.

        Return the original state of the endpoint_group, prior to a call to
        update_endpoint_group. Method is only valid within calls to
        update_endpoint_group_precommit and update_endpoint_group_postcommit.
        """
        pass


@six.add_metaclass(ABCMeta)
class PolicyDriver(object):
    """Define stable abstract interface for Group Policy drivers.

    A policy driver is called on the creation, update, and deletion
    of all Group Policy resources. For every event, there are two methods that
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
    case of update of resources, all data validation must be done within
    methods that are part of the database transaction.
    """

    @abstractmethod
    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        pass

    def create_endpoint_precommit(self, context):
        """Allocate resources for a new endpoint.

        :param context: EndpointContext instance describing the new
        endpoint.

        Create a new endpoint, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_endpoint_postcommit(self, context):
        """Create a endpoint.

        :param context: EndpointContext instance describing the new
        endpoint.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_endpoint_precommit(self, context):
        """Update resources of a endpoint.

        :param context: EndpointContext instance describing the new
        state of the endpoint, as well as the original state prior
        to the update_endpoint call.

        Update values of a endpoint, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_endpoint_precommit is called for all changes to the
        endpoint state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_endpoint_postcommit(self, context):
        """Update a endpoint.

        :param context: EndpointContext instance describing the new
        state of the endpoint, as well as the original state prior
        to the update_endpoint call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_endpoint_postcommit is called for all changes to the
        endpoint state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_endpoint_precommit(self, context):
        """Delete resources for a endpoint.

        :param context: EndpointContext instance describing the current
        state of the endpoint, prior to the call to delete it.

        Delete endpoint resources previously allocated by this
        mechanism driver for a endpoint. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    def delete_endpoint_postcommit(self, context):
        """Delete a endpoint.

        :param context: EndpointContext instance describing the current
        state of the endpoint, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_endpoint_group_precommit(self, context):
        """Allocate resources for a new endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        endpoint_group.

        Create a new endpoint_group, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_endpoint_group_postcommit(self, context):
        """Create a endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        endpoint_group.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        pass

    def update_endpoint_group_precommit(self, context):
        """Update resources of a endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        state of the endpoint_group, as well as the original state prior
        to the update_endpoint_group call.

        Update values of a endpoint_group, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_endpoint_group_precommit is called for all changes to the
        endpoint_group state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_endpoint_group_postcommit(self, context):
        """Update a endpoint_group.

        :param context: EndpointGroupContext instance describing the new
        state of the endpoint_group, as well as the original state prior
        to the update_endpoint_group call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_endpoint_group_postcommit is called for all changes to the
        endpoint_group state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_endpoint_group_precommit(self, context):
        """Delete resources for a endpoint_group.

        :param context: EndpointGroupContext instance describing the current
        state of the endpoint_group, prior to the call to delete it.

        Delete endpoint_group resources previously allocated by this
        mechanism driver for a endpoint_group. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    def delete_endpoint_group_postcommit(self, context):
        """Delete a endpoint_group.

        :param context: EndpointGroupContext instance describing the current
        state of the endpoint_group, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass
