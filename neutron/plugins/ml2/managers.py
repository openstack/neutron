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

from oslo.config import cfg
import stevedore

from neutron.common import exceptions as exc
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api


LOG = log.getLogger(__name__)


class TypeManager(stevedore.named.NamedExtensionManager):
    """Manage network segment types using drivers."""

    def __init__(self):
        # Mapping from type name to DriverManager
        self.drivers = {}

        LOG.info(_("Configured type driver names: %s"),
                 cfg.CONF.ml2.type_drivers)
        super(TypeManager, self).__init__('neutron.ml2.type_drivers',
                                          cfg.CONF.ml2.type_drivers,
                                          invoke_on_load=True)
        LOG.info(_("Loaded type driver names: %s"), self.names())
        self._register_types()
        self._check_tenant_network_types(cfg.CONF.ml2.tenant_network_types)

    def _register_types(self):
        for ext in self:
            network_type = ext.obj.get_type()
            if network_type in self.drivers:
                LOG.error(_("Type driver '%(new_driver)s' ignored because type"
                            " driver '%(old_driver)s' is already registered"
                            " for type '%(type)s'"),
                          {'new_driver': ext.name,
                           'old_driver': self.drivers[network_type].name,
                           'type': network_type})
            else:
                self.drivers[network_type] = ext
        LOG.info(_("Registered types: %s"), self.drivers.keys())

    def _check_tenant_network_types(self, types):
        self.tenant_network_types = []
        for network_type in types:
            if network_type in self.drivers:
                self.tenant_network_types.append(network_type)
            else:
                msg = _("No type driver for tenant network_type: %s. "
                        "Service terminated!") % network_type
                LOG.error(msg)
                raise SystemExit(msg)
        LOG.info(_("Tenant network_types: %s"), self.tenant_network_types)

    def initialize(self):
        for network_type, driver in self.drivers.iteritems():
            LOG.info(_("Initializing driver for type '%s'"), network_type)
            driver.obj.initialize()

    def validate_provider_segment(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        driver = self.drivers.get(network_type)
        if driver:
            driver.obj.validate_provider_segment(segment)
        else:
            msg = _("network_type value '%s' not supported") % network_type
            raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        driver.obj.reserve_provider_segment(session, segment)

    def allocate_tenant_segment(self, session):
        for network_type in self.tenant_network_types:
            driver = self.drivers.get(network_type)
            segment = driver.obj.allocate_tenant_segment(session)
            if segment:
                return segment
        raise exc.NoNetworkAvailable()

    def release_segment(self, session, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        # ML2 may have been reconfigured since the segment was created,
        # so a driver may no longer exist for this network_type.
        # REVISIT: network_type-specific db entries may become orphaned
        # if a network is deleted and the driver isn't available to release
        # the segment. This may be fixed with explicit foreign-key references
        # or consistency checks on driver initialization.
        if not driver:
            LOG.error(_("Failed to release segment '%s' because "
                        "network type is not supported."), segment)
            return
        driver.obj.release_segment(session, segment)


class MechanismManager(stevedore.named.NamedExtensionManager):
    """Manage networking mechanisms using drivers."""

    def __init__(self):
        # Registered mechanism drivers, keyed by name.
        self.mech_drivers = {}
        # Ordered list of mechanism drivers, defining
        # the order in which the drivers are called.
        self.ordered_mech_drivers = []

        LOG.info(_("Configured mechanism driver names: %s"),
                 cfg.CONF.ml2.mechanism_drivers)
        super(MechanismManager, self).__init__('neutron.ml2.mechanism_drivers',
                                               cfg.CONF.ml2.mechanism_drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info(_("Loaded mechanism driver names: %s"), self.names())
        self._register_mechanisms()

    def _register_mechanisms(self):
        """Register all mechanism drivers.

        This method should only be called once in the MechanismManager
        constructor.
        """
        for ext in self:
            self.mech_drivers[ext.name] = ext
            self.ordered_mech_drivers.append(ext)
        LOG.info(_("Registered mechanism drivers: %s"),
                 [driver.name for driver in self.ordered_mech_drivers])

    def initialize(self):
        # For ML2 to support bulk operations, each driver must support them
        self.native_bulk_support = True
        for driver in self.ordered_mech_drivers:
            LOG.info(_("Initializing mechanism driver '%s'"), driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_on_drivers(self, method_name, context,
                         continue_on_failure=False):
        """Helper method for calling a method across all mechanism drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all mechanism drivers once one has raised an exception
        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver call fails.
        """
        error = False
        for driver in self.ordered_mech_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception:
                LOG.exception(
                    _("Mechanism driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )
                error = True
                if not continue_on_failure:
                    break
        if error:
            raise ml2_exc.MechanismDriverError(
                method=method_name
            )

    def create_network_precommit(self, context):
        """Notify all mechanism drivers during network creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_network_precommit", context)

    def create_network_postcommit(self, context):
        """Notify all mechanism drivers after network creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_network_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the network will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("create_network_postcommit", context)

    def update_network_precommit(self, context):
        """Notify all mechanism drivers during network update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_network_precommit", context)

    def update_network_postcommit(self, context):
        """Notify all mechanism drivers after network update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_network_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where an error is returned to the user. The
        user is expected to take the appropriate action, whether by
        retrying the call or deleting the network. There is no
        guarantee that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_network_postcommit", context)

    def delete_network_precommit(self, context):
        """Notify all mechanism drivers during network deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_network_precommit", context)

    def delete_network_postcommit(self, context):
        """Notify all mechanism drivers after network deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_network_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        network resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        network.
        """
        self._call_on_drivers("delete_network_postcommit", context,
                              continue_on_failure=True)

    def create_subnet_precommit(self, context):
        """Notify all mechanism drivers during subnet creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_subnet_precommit", context)

    def create_subnet_postcommit(self, context):
        """Notify all mechanism drivers after subnet creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_subnet_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the subnet will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("create_subnet_postcommit", context)

    def update_subnet_precommit(self, context):
        """Notify all mechanism drivers during subnet update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_subnet_precommit", context)

    def update_subnet_postcommit(self, context):
        """Notify all mechanism drivers after subnet update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_subnet_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where an error is returned to the user. The
        user is expected to take the appropriate action, whether by
        retrying the call or deleting the subnet. There is no
        guarantee that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_subnet_postcommit", context)

    def delete_subnet_precommit(self, context):
        """Notify all mechanism drivers during subnet deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_subnet_precommit", context)

    def delete_subnet_postcommit(self, context):
        """Notify all mechanism drivers after subnet deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_subnet_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        subnet resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        subnet.
        """
        self._call_on_drivers("delete_subnet_postcommit", context,
                              continue_on_failure=True)

    def create_port_precommit(self, context):
        """Notify all mechanism drivers during port creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_port_precommit", context)

    def create_port_postcommit(self, context):
        """Notify all mechanism drivers of port creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_port_postcommit call fails.

        Called after the database transaction. Errors raised by
        mechanism drivers are left to propagate to the caller, where
        the port will be deleted, triggering any required
        cleanup. There is no guarantee that all mechanism drivers are
        called in this case.
        """
        self._call_on_drivers("create_port_postcommit", context)

    def update_port_precommit(self, context):
        """Notify all mechanism drivers during port update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_port_precommit", context)

    def update_port_postcommit(self, context):
        """Notify all mechanism drivers after port update.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_port_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where an error is returned to the user. The
        user is expected to take the appropriate action, whether by
        retrying the call or deleting the port. There is no
        guarantee that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_port_postcommit", context)

    def delete_port_precommit(self, context):
        """Notify all mechanism drivers during port deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_port_precommit", context)

    def delete_port_postcommit(self, context):
        """Notify all mechanism drivers after port deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_port_postcommit call fails.

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure. In
        general we expect the caller to ignore the error, as the
        port resource has already been deleted from the database
        and it doesn't make sense to undo the action by recreating the
        port.
        """
        self._call_on_drivers("delete_port_postcommit", context,
                              continue_on_failure=True)

    def bind_port(self, context):
        """Attempt to bind a port using registered mechanism drivers.

        :param context: PortContext instance describing the port

        Called inside transaction context on session, prior to
        create_port_precommit or update_port_precommit, to
        attempt to establish a port binding.
        """
        binding = context._binding
        LOG.debug(_("Attempting to bind port %(port)s on host %(host)s "
                    "for vnic_type %(vnic_type)s with profile %(profile)s"),
                  {'port': context._port['id'],
                   'host': binding.host,
                   'vnic_type': binding.vnic_type,
                   'profile': binding.profile})
        for driver in self.ordered_mech_drivers:
            try:
                driver.obj.bind_port(context)
                if binding.segment:
                    binding.driver = driver.name
                    LOG.debug(_("Bound port: %(port)s, host: %(host)s, "
                                "vnic_type: %(vnic_type)s, "
                                "profile: %(profile)s"
                                "driver: %(driver)s, vif_type: %(vif_type)s, "
                                "vif_details: %(vif_details)s, "
                                "segment: %(segment)s"),
                              {'port': context._port['id'],
                               'host': binding.host,
                               'vnic_type': binding.vnic_type,
                               'profile': binding.profile,
                               'driver': binding.driver,
                               'vif_type': binding.vif_type,
                               'vif_details': binding.vif_details,
                               'segment': binding.segment})
                    return
            except Exception:
                LOG.exception(_("Mechanism driver %s failed in "
                                "bind_port"),
                              driver.name)
        binding.vif_type = portbindings.VIF_TYPE_BINDING_FAILED
        LOG.warning(_("Failed to bind port %(port)s on host %(host)s"),
                    {'port': context._port['id'],
                     'host': binding.host})
