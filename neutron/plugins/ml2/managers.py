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

from oslo_config import cfg
import stevedore

from neutron.api.v2 import attributes
from neutron.common import exceptions as exc
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.i18n import _LE, _LI
from neutron.openstack.common import log
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class TypeManager(stevedore.named.NamedExtensionManager):
    """Manage network segment types using drivers."""

    def __init__(self):
        # Mapping from type name to DriverManager
        self.drivers = {}

        LOG.info(_LI("Configured type driver names: %s"),
                 cfg.CONF.ml2.type_drivers)
        super(TypeManager, self).__init__('neutron.ml2.type_drivers',
                                          cfg.CONF.ml2.type_drivers,
                                          invoke_on_load=True)
        LOG.info(_LI("Loaded type driver names: %s"), self.names())
        self._register_types()
        self._check_tenant_network_types(cfg.CONF.ml2.tenant_network_types)

    def _register_types(self):
        for ext in self:
            network_type = ext.obj.get_type()
            if network_type in self.drivers:
                LOG.error(_LE("Type driver '%(new_driver)s' ignored because"
                              " type driver '%(old_driver)s' is already"
                              " registered for type '%(type)s'"),
                          {'new_driver': ext.name,
                           'old_driver': self.drivers[network_type].name,
                           'type': network_type})
            else:
                self.drivers[network_type] = ext
        LOG.info(_LI("Registered types: %s"), self.drivers.keys())

    def _check_tenant_network_types(self, types):
        self.tenant_network_types = []
        for network_type in types:
            if network_type in self.drivers:
                self.tenant_network_types.append(network_type)
            else:
                LOG.error(_LE("No type driver for tenant network_type: %s. "
                              "Service terminated!"), network_type)
                raise SystemExit(1)
        LOG.info(_LI("Tenant network_types: %s"), self.tenant_network_types)

    def _process_provider_segment(self, segment):
        (network_type, physical_network,
         segmentation_id) = (self._get_attribute(segment, attr)
                             for attr in provider.ATTRIBUTES)

        if attributes.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            self.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _get_segment_attributes(self, network):
        return {attr: self._get_attribute(network, attr)
                for attr in provider.ATTRIBUTES}

    def _process_provider_create(self, network):
        if any(attributes.is_attr_set(network.get(attr))
               for attr in provider.ATTRIBUTES):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()

            segments = [self._get_segment_attributes(network)]
            return [self._process_provider_segment(s) for s in segments]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = [self._process_provider_segment(s)
                        for s in network[mpnet.SEGMENTS]]
            mpnet.check_duplicate_segments(
                segments,
                self.is_partial_segment)
            return segments

    def _get_attribute(self, attrs, key):
        value = attrs.get(key)
        if value is attributes.ATTR_NOT_SPECIFIED:
            value = None
        return value

    def _extend_network_dict_provider(self, context, network):
        id = network['id']
        segments = db.get_network_segments(context.session, id)
        if not segments:
            LOG.error(_LE("Network %s has no segments"), id)
            for attr in provider.ATTRIBUTES:
                network[attr] = None
        elif len(segments) > 1:
            network[mpnet.SEGMENTS] = [
                {provider.NETWORK_TYPE: segment[api.NETWORK_TYPE],
                 provider.PHYSICAL_NETWORK: segment[api.PHYSICAL_NETWORK],
                 provider.SEGMENTATION_ID: segment[api.SEGMENTATION_ID]}
                for segment in segments]
        else:
            segment = segments[0]
            network[provider.NETWORK_TYPE] = segment[api.NETWORK_TYPE]
            network[provider.PHYSICAL_NETWORK] = segment[api.PHYSICAL_NETWORK]
            network[provider.SEGMENTATION_ID] = segment[api.SEGMENTATION_ID]

    def initialize(self):
        for network_type, driver in self.drivers.iteritems():
            LOG.info(_LI("Initializing driver for type '%s'"), network_type)
            driver.obj.initialize()

    def create_network_segments(self, context, network, tenant_id):
        """Call type drivers to create network segments."""
        segments = self._process_provider_create(network)
        session = context.session
        with session.begin(subtransactions=True):
            network_id = network['id']
            if segments:
                for segment_index, segment in enumerate(segments):
                    segment = self.reserve_provider_segment(
                        session, segment)
                    db.add_network_segment(session, network_id,
                                           segment, segment_index)
            else:
                segment = self.allocate_tenant_segment(session)
                db.add_network_segment(session, network_id, segment)

    def is_partial_segment(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        driver = self.drivers.get(network_type)
        if driver:
            return driver.obj.is_partial_segment(segment)
        else:
            msg = _("network_type value '%s' not supported") % network_type
            raise exc.InvalidInput(error_message=msg)

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
        return driver.obj.reserve_provider_segment(session, segment)

    def allocate_tenant_segment(self, session):
        for network_type in self.tenant_network_types:
            driver = self.drivers.get(network_type)
            segment = driver.obj.allocate_tenant_segment(session)
            if segment:
                return segment
        raise exc.NoNetworkAvailable()

    def release_network_segments(self, session, network_id):
        segments = db.get_network_segments(session, network_id,
                                           filter_dynamic=None)

        for segment in segments:
            network_type = segment.get(api.NETWORK_TYPE)
            driver = self.drivers.get(network_type)
            if driver:
                driver.obj.release_segment(session, segment)
            else:
                LOG.error(_LE("Failed to release segment '%s' because "
                              "network type is not supported."), segment)

    def allocate_dynamic_segment(self, session, network_id, segment):
        """Allocate a dynamic segment using a partial or full segment dict."""
        dynamic_segment = db.get_dynamic_segment(
            session, network_id, segment.get(api.PHYSICAL_NETWORK),
            segment.get(api.SEGMENTATION_ID))

        if dynamic_segment:
            return dynamic_segment

        driver = self.drivers.get(segment.get(api.NETWORK_TYPE))
        dynamic_segment = driver.obj.reserve_provider_segment(session, segment)
        db.add_network_segment(session, network_id, dynamic_segment,
                               is_dynamic=True)
        return dynamic_segment

    def release_dynamic_segment(self, session, segment_id):
        """Delete a dynamic segment."""
        segment = db.get_segment_by_id(session, segment_id)
        if segment:
            driver = self.drivers.get(segment.get(api.NETWORK_TYPE))
            if driver:
                driver.obj.release_segment(session, segment)
                db.delete_network_segment(session, segment_id)
            else:
                LOG.error(_LE("Failed to release segment '%s' because "
                              "network type is not supported."), segment)
        else:
            LOG.debug("No segment found with id %(segment_id)s", segment_id)


class MechanismManager(stevedore.named.NamedExtensionManager):
    """Manage networking mechanisms using drivers."""

    def __init__(self):
        # Registered mechanism drivers, keyed by name.
        self.mech_drivers = {}
        # Ordered list of mechanism drivers, defining
        # the order in which the drivers are called.
        self.ordered_mech_drivers = []

        LOG.info(_LI("Configured mechanism driver names: %s"),
                 cfg.CONF.ml2.mechanism_drivers)
        super(MechanismManager, self).__init__('neutron.ml2.mechanism_drivers',
                                               cfg.CONF.ml2.mechanism_drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info(_LI("Loaded mechanism driver names: %s"), self.names())
        self._register_mechanisms()

    def _register_mechanisms(self):
        """Register all mechanism drivers.

        This method should only be called once in the MechanismManager
        constructor.
        """
        for ext in self:
            self.mech_drivers[ext.name] = ext
            self.ordered_mech_drivers.append(ext)
        LOG.info(_LI("Registered mechanism drivers: %s"),
                 [driver.name for driver in self.ordered_mech_drivers])

    def initialize(self):
        for driver in self.ordered_mech_drivers:
            LOG.info(_LI("Initializing mechanism driver '%s'"), driver.name)
            driver.obj.initialize()

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
                    _LE("Mechanism driver '%(name)s' failed in %(method)s"),
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

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_network_postcommit", context,
                              continue_on_failure=True)

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

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_subnet_postcommit", context,
                              continue_on_failure=True)

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

        Called after the database transaction. If any mechanism driver
        raises an error, then the error is logged but we continue to
        call every other mechanism driver. A MechanismDriverError is
        then reraised at the end to notify the caller of a failure.
        """
        self._call_on_drivers("update_port_postcommit", context,
                              continue_on_failure=True)

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

        Called outside any transaction to attempt to establish a port
        binding.
        """
        binding = context._binding
        LOG.debug("Attempting to bind port %(port)s on host %(host)s "
                  "for vnic_type %(vnic_type)s with profile %(profile)s",
                  {'port': context._port['id'],
                   'host': binding.host,
                   'vnic_type': binding.vnic_type,
                   'profile': binding.profile})
        for driver in self.ordered_mech_drivers:
            try:
                driver.obj.bind_port(context)
                if binding.segment:
                    binding.driver = driver.name
                    LOG.debug("Bound port: %(port)s, host: %(host)s, "
                              "vnic_type: %(vnic_type)s, "
                              "profile: %(profile)s, "
                              "driver: %(driver)s, vif_type: %(vif_type)s, "
                              "vif_details: %(vif_details)s, "
                              "segment: %(segment)s",
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
                LOG.exception(_LE("Mechanism driver %s failed in "
                                  "bind_port"),
                              driver.name)
        binding.vif_type = portbindings.VIF_TYPE_BINDING_FAILED
        LOG.error(_LE("Failed to bind port %(port)s on host %(host)s"),
                  {'port': context._port['id'],
                   'host': binding.host})


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extension drivers using drivers."""

    def __init__(self):
        # Ordered list of extension drivers, defining
        # the order in which the drivers are called.
        self.ordered_ext_drivers = []

        LOG.info(_LI("Configured extension driver names: %s"),
                 cfg.CONF.ml2.extension_drivers)
        super(ExtensionManager, self).__init__('neutron.ml2.extension_drivers',
                                               cfg.CONF.ml2.extension_drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info(_LI("Loaded extension driver names: %s"), self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        for ext in self:
            self.ordered_ext_drivers.append(ext)
        LOG.info(_LI("Registered extension drivers: %s"),
                 [driver.name for driver in self.ordered_ext_drivers])

    def initialize(self):
        # Initialize each driver in the list.
        for driver in self.ordered_ext_drivers:
            LOG.info(_LI("Initializing extension driver '%s'"), driver.name)
            driver.obj.initialize()

    def extension_aliases(self):
        exts = []
        for driver in self.ordered_ext_drivers:
            alias = driver.obj.extension_alias
            exts.append(alias)
            LOG.info(_LI("Got %(alias)s extension from driver '%(drv)s'"),
                     {'alias': alias, 'drv': driver.name})
        return exts

    def _call_on_ext_drivers(self, method_name, session, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(session, data, result)
            except Exception:
                LOG.exception(
                    _LE("Extension driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )

    def process_create_network(self, session, data, result):
        """Notify all extension drivers during network creation."""
        self._call_on_ext_drivers("process_create_network", session, data,
                                  result)

    def process_update_network(self, session, data, result):
        """Notify all extension drivers during network update."""
        self._call_on_ext_drivers("process_update_network", session, data,
                                  result)

    def process_create_subnet(self, session, data, result):
        """Notify all extension drivers during subnet creation."""
        self._call_on_ext_drivers("process_create_subnet", session, data,
                                  result)

    def process_update_subnet(self, session, data, result):
        """Notify all extension drivers during subnet update."""
        self._call_on_ext_drivers("process_update_subnet", session, data,
                                  result)

    def process_create_port(self, session, data, result):
        """Notify all extension drivers during port creation."""
        self._call_on_ext_drivers("process_create_port", session, data, result)

    def process_update_port(self, session, data, result):
        """Notify all extension drivers during port update."""
        self._call_on_ext_drivers("process_update_port", session, data, result)

    def extend_network_dict(self, session, result):
        """Notify all extension drivers to extend network dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_network_dict(session, result)
            LOG.info(_LI("Extended network dict for driver '%(drv)s'"),
                     {'drv': driver.name})

    def extend_subnet_dict(self, session, result):
        """Notify all extension drivers to extend subnet dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_subnet_dict(session, result)
            LOG.info(_LI("Extended subnet dict for driver '%(drv)s'"),
                     {'drv': driver.name})

    def extend_port_dict(self, session, result):
        """Notify all extension drivers to extend port dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_port_dict(session, result)
            LOG.info(_LI("Extended port dict for driver '%(drv)s'"),
                     {'drv': driver.name})
