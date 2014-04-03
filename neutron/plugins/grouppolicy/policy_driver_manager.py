# Copyright (c) 2014 OpenStack Foundation
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

from oslo.config import cfg
import stevedore

from neutron.openstack.common import log
from neutron.plugins.grouppolicy.common import exceptions as gp_exc


LOG = log.getLogger(__name__)


class PolicyDriverManager(stevedore.named.NamedExtensionManager):
    """Manage group policy enforcement using drivers."""

    def __init__(self):
        # Registered policy drivers, keyed by name.
        self.policy_drivers = {}
        # Ordered list of policy drivers, defining
        # the order in which the drivers are called.
        self.ordered_policy_drivers = []

        LOG.info(_("Configured policy driver names: %s"),
                 cfg.CONF.group_policy.policy_drivers)
        super(PolicyDriverManager,
              self).__init__('neutron.group_policy.policy_drivers',
                             cfg.CONF.group_policy.policy_drivers,
                             invoke_on_load=True,
                             name_order=True)
        LOG.info(_("Loaded policy driver names: %s"), self.names())
        self._register_policy_drivers()

    def _register_policy_drivers(self):
        """Register all policy drivers.

        This method should only be called once in the PolicDriverManager
        constructor.
        """
        for ext in self:
            self.policy_drivers[ext.name] = ext
            self.ordered_policy_drivers.append(ext)
        LOG.info(_("Registered policy drivers: %s"),
                 [driver.name for driver in self.ordered_policy_drivers])

    def initialize(self):
        # Group Policy bulk operations requires each driver to support them
        self.native_bulk_support = True
        for driver in self.ordered_policy_drivers:
            LOG.info(_("Initializing policy driver '%s'"), driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_on_drivers(self, method_name, context,
                         continue_on_failure=False):
        """Helper method for calling a method across all policy drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all policy drivers once one has raised an exception
        :raises: neutron.plugins.group_policy.common.GroupPolicyDriverError
        if any policy driver call fails.
        """
        error = False
        for driver in self.ordered_policy_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception:
                LOG.exception(
                    _("Policy driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )
                error = True
                if not continue_on_failure:
                    break
        if error:
            raise gp_exc.GroupPolicyDriverError(
                method=method_name
            )

    def create_endpoint_precommit(self, context):
        """Notify all policy drivers during endpoint creation.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver create_endpoint_precommit call fails.

        Called within the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all policy drivers are called in this case.
        """
        self._call_on_drivers("create_endpoint_precommit", context)

    def create_endpoint_postcommit(self, context):
        """Notify all policy drivers after endpoint creation.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver create_endpoint_postcommit call fails.

        Called after the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propagated
        to the caller, where the endpoint will be deleted, triggering
        any required cleanup. There is no guarantee that all policy
        drivers are called in this case.
        """
        self._call_on_drivers("create_endpoint_postcommit", context)

    def update_endpoint_precommit(self, context):
        """Notify all policy drivers during endpoint update.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver update_endpoint_precommit call fails.

        Called within the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all policy drivers are called in this case.
        """
        self._call_on_drivers("update_endpoint_precommit", context)

    def update_endpoint_postcommit(self, context):
        """Notify all policy drivers after endpoint update.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver update_endpoint_postcommit call fails.

        Called after the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propagated
        to the caller, where an error is returned to the user. The
        user is expected to take the appropriate action, whether by
        retrying the call or deleting the endpoint. There is no
        guarantee that all policy drivers are called in this case.
        """
        self._call_on_drivers("update_endpoint_postcommit", context)

    def delete_endpoint_precommit(self, context):
        """Notify all policy drivers during endpoint deletion.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver delete_endpoint_precommit call fails.

        Called within the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all policy drivers are called in this case.
        """
        self._call_on_drivers("delete_endpoint_precommit", context)

    def delete_endpoint_postcommit(self, context):
        """Notify all policy drivers after endpoint deletion.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver delete_endpoint_postcommit call fails.

        Called after the database transaction. If any policy driver
        raises an error, then the error is logged but we continue to
        call every other policy driver. A GroupPolicyDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        endpoint resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        endpoint.
        """
        self._call_on_drivers("delete_endpoint_postcommit", context,
                              continue_on_failure=True)

    def create_endpoint_group_precommit(self, context):
        """Notify all policy drivers during endpoint_group creation.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver create_endpoint_group_precommit call fails.

        Called within the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all policy drivers are called in this case.
        """
        self._call_on_drivers("create_endpoint_group_precommit", context)

    def create_endpoint_group_postcommit(self, context):
        """Notify all policy drivers after endpoint_group creation.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver create_endpoint_group_postcommit call fails.

        Called after the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propagated
        to the caller, where the endpoint_group will be deleted, triggering
        any required cleanup. There is no guarantee that all policy
        drivers are called in this case.
        """
        self._call_on_drivers("create_endpoint_group_postcommit", context)

    def update_endpoint_group_precommit(self, context):
        """Notify all policy drivers during endpoint_group update.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver update_endpoint_group_precommit call fails.

        Called within the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all policy drivers are called in this case.
        """
        self._call_on_drivers("update_endpoint_group_precommit", context)

    def update_endpoint_group_postcommit(self, context):
        """Notify all policy drivers after endpoint_group update.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver update_endpoint_group_postcommit call fails.

        Called after the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propagated
        to the caller, where an error is returned to the user. The
        user is expected to take the appropriate action, whether by
        retrying the call or deleting the endpoint_group. There is no
        guarantee that all policy drivers are called in this case.
        """
        self._call_on_drivers("update_endpoint_group_postcommit", context)

    def delete_endpoint_group_precommit(self, context):
        """Notify all policy drivers during endpoint_group deletion.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver delete_endpoint_group_precommit call fails.

        Called within the database transaction. If a policy driver
        raises an exception, then a GroupPolicyDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all policy drivers are called in this case.
        """
        self._call_on_drivers("delete_endpoint_group_precommit", context)

    def delete_endpoint_group_postcommit(self, context):
        """Notify all policy drivers after endpoint_group deletion.

        :raises: neutron.plugins.grouppolicy.common.GroupPolicyDriverError
        if any policy driver delete_endpoint_group_postcommit call fails.

        Called after the database transaction. If any policy driver
        raises an error, then the error is logged but we continue to
        call every other policy driver. A GroupPolicyDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        endpoint_group resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        endpoint_group.
        """
        self._call_on_drivers("delete_endpoint_group_postcommit", context,
                              continue_on_failure=True)
