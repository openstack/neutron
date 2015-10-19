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
from oslo_log import log
import stevedore

from neutron.api.v2 import attributes
from neutron.common import exceptions as exc
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.extensions import vlantransparent
from neutron.i18n import _LE, _LI
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import models

LOG = log.getLogger(__name__)

MAX_BINDING_LEVELS = 10


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

    def _process_provider_create(self, network):
        if any(attributes.is_attr_set(network.get(attr))
               for attr in provider.ATTRIBUTES):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()
            segment = self._get_provider_segment(network)
            return [self._process_provider_segment(segment)]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = [self._process_provider_segment(s)
                        for s in network[mpnet.SEGMENTS]]
            mpnet.check_duplicate_segments(
                segments,
                self.is_partial_segment)
            return segments

    def _match_segment(self, segment, filters):
        return all(not filters.get(attr) or segment.get(attr) in filters[attr]
                   for attr in provider.ATTRIBUTES)

    def _get_provider_segment(self, network):
        # TODO(manishg): Placeholder method
        # Code intended for operating on a provider segment should use
        # this method to extract the segment, even though currently the
        # segment attributes are part of the network dictionary. In the
        # future, network and segment information will be decoupled and
        # here we will do the job of extracting the segment information.
        return network

    def network_matches_filters(self, network, filters):
        if not filters:
            return True
        if any(attributes.is_attr_set(network.get(attr))
               for attr in provider.ATTRIBUTES):
            segments = [self._get_provider_segment(network)]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = self._get_attribute(network, mpnet.SEGMENTS)
        else:
            return True
        return any(self._match_segment(s, filters) for s in segments)

    def _get_attribute(self, attrs, key):
        value = attrs.get(key)
        if value is attributes.ATTR_NOT_SPECIFIED:
            value = None
        return value

    def extend_network_dict_provider(self, context, network):
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
        mtu = []
        with session.begin(subtransactions=True):
            network_id = network['id']
            if segments:
                for segment_index, segment in enumerate(segments):
                    segment = self.reserve_provider_segment(
                        session, segment)
                    db.add_network_segment(session, network_id,
                                           segment, segment_index)
                    if segment.get(api.MTU) > 0:
                        mtu.append(segment[api.MTU])
            else:
                segment = self.allocate_tenant_segment(session)
                db.add_network_segment(session, network_id, segment)
                if segment.get(api.MTU) > 0:
                    mtu.append(segment[api.MTU])
        network[api.MTU] = min(mtu) if mtu else 0

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

    def _check_vlan_transparency(self, context):
        """Helper method for checking vlan transparecncy support.

        :param context: context parameter to pass to each method call
        :raises: neutron.extensions.vlantransparent.
        VlanTransparencyDriverError if any mechanism driver doesn't
        support vlan transparency.
        """
        if context.current['vlan_transparent'] is None:
            return

        if context.current['vlan_transparent']:
            for driver in self.ordered_mech_drivers:
                if not driver.obj.check_vlan_transparency(context):
                    raise vlantransparent.VlanTransparencyDriverError()

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
        self._check_vlan_transparency(context)
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
                  {'port': context.current['id'],
                   'host': context.host,
                   'vnic_type': binding.vnic_type,
                   'profile': binding.profile})
        context._clear_binding_levels()
        if not self._bind_port_level(context, 0,
                                     context.network.network_segments):
            binding.vif_type = portbindings.VIF_TYPE_BINDING_FAILED
            LOG.error(_LE("Failed to bind port %(port)s on host %(host)s"),
                      {'port': context.current['id'],
                       'host': context.host})

    def _bind_port_level(self, context, level, segments_to_bind):
        binding = context._binding
        port_id = context._port['id']
        LOG.debug("Attempting to bind port %(port)s on host %(host)s "
                  "at level %(level)s using segments %(segments)s",
                  {'port': port_id,
                   'host': context.host,
                   'level': level,
                   'segments': segments_to_bind})

        if level == MAX_BINDING_LEVELS:
            LOG.error(_LE("Exceeded maximum binding levels attempting to bind "
                        "port %(port)s on host %(host)s"),
                      {'port': context.current['id'],
                       'host': context.host})
            return False

        for driver in self.ordered_mech_drivers:
            if not self._check_driver_to_bind(driver, segments_to_bind,
                                              context._binding_levels):
                continue
            try:
                context._prepare_to_bind(segments_to_bind)
                driver.obj.bind_port(context)
                segment = context._new_bound_segment
                if segment:
                    context._push_binding_level(
                        models.PortBindingLevel(port_id=port_id,
                                                host=context.host,
                                                level=level,
                                                driver=driver.name,
                                                segment_id=segment))
                    next_segments = context._next_segments_to_bind
                    if next_segments:
                        # Continue binding another level.
                        if self._bind_port_level(context, level + 1,
                                                 next_segments):
                            return True
                        else:
                            context._pop_binding_level()
                    else:
                        # Binding complete.
                        LOG.debug("Bound port: %(port)s, "
                                  "host: %(host)s, "
                                  "vif_type: %(vif_type)s, "
                                  "vif_details: %(vif_details)s, "
                                  "binding_levels: %(binding_levels)s",
                                  {'port': port_id,
                                   'host': context.host,
                                   'vif_type': binding.vif_type,
                                   'vif_details': binding.vif_details,
                                   'binding_levels': context.binding_levels})
                        return True
            except Exception:
                LOG.exception(_LE("Mechanism driver %s failed in "
                                  "bind_port"),
                              driver.name)
        binding.vif_type = portbindings.VIF_TYPE_BINDING_FAILED
        LOG.error(_LE("Failed to bind port %(port)s on host %(host)s"),
                  {'port': context._port['id'],
                   'host': binding.host})

    def _check_driver_to_bind(self, driver, segments_to_bind, binding_levels):
        # To prevent a possible binding loop, don't try to bind with
        # this driver if the same driver has already bound at a higher
        # level to one of the segments we are currently trying to
        # bind. Note that is is OK for the same driver to bind at
        # multiple levels using different segments.
        for level in binding_levels:
            if (level.driver == driver and
                level.segment_id in segments_to_bind):
                return False
        return True


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

    def _call_on_ext_drivers(self, method_name, plugin_context, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(plugin_context, data, result)
            except Exception:
                LOG.exception(
                    _LE("Extension driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )

    def process_create_network(self, plugin_context, data, result):
        """Notify all extension drivers during network creation."""
        self._call_on_ext_drivers("process_create_network", plugin_context,
                                  data, result)

    def process_update_network(self, plugin_context, data, result):
        """Notify all extension drivers during network update."""
        self._call_on_ext_drivers("process_update_network", plugin_context,
                                  data, result)

    def process_create_subnet(self, plugin_context, data, result):
        """Notify all extension drivers during subnet creation."""
        self._call_on_ext_drivers("process_create_subnet", plugin_context,
                                  data, result)

    def process_update_subnet(self, plugin_context, data, result):
        """Notify all extension drivers during subnet update."""
        self._call_on_ext_drivers("process_update_subnet", plugin_context,
                                  data, result)

    def process_create_port(self, plugin_context, data, result):
        """Notify all extension drivers during port creation."""
        self._call_on_ext_drivers("process_create_port", plugin_context,
                                  data, result)

    def process_update_port(self, plugin_context, data, result):
        """Notify all extension drivers during port update."""
        self._call_on_ext_drivers("process_update_port", plugin_context,
                                  data, result)

    def extend_network_dict(self, session, base_model, result):
        """Notify all extension drivers to extend network dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_network_dict(session, base_model, result)
            LOG.debug("Extended network dict for driver '%(drv)s'",
                      {'drv': driver.name})

    def extend_subnet_dict(self, session, base_model, result):
        """Notify all extension drivers to extend subnet dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_subnet_dict(session, base_model, result)
            LOG.debug("Extended subnet dict for driver '%(drv)s'",
                      {'drv': driver.name})

    def extend_port_dict(self, session, base_model, result):
        """Notify all extension drivers to extend port dictionary."""
        for driver in self.ordered_ext_drivers:
            driver.obj.extend_port_dict(session, base_model, result)
            LOG.debug("Extended port dict for driver '%(drv)s'",
                      {'drv': driver.name})
