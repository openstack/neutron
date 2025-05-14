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

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import multiprovidernet as mpnet_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as provider
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from neutron_lib.exceptions import multiprovidernet as mpnet_exc
from neutron_lib.exceptions import placement as place_exc
from neutron_lib.exceptions import vlantransparent as vlan_exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
import stevedore

from neutron._i18n import _
from neutron.conf.plugins.ml2 import config
from neutron.db import segments_db
from neutron.objects import ports
from neutron.plugins.ml2.common import exceptions as ml2_exc

LOG = log.getLogger(__name__)

MAX_BINDING_LEVELS = 10
config.register_ml2_plugin_opts()


class TypeManager(stevedore.named.NamedExtensionManager):
    """Manage network segment types using drivers."""

    def __init__(self):
        # Mapping from type name to DriverManager
        self.drivers = {}

        LOG.info("Configured type driver names: %s",
                 cfg.CONF.ml2.type_drivers)
        super(TypeManager, self).__init__('neutron.ml2.type_drivers',
                                          cfg.CONF.ml2.type_drivers,
                                          invoke_on_load=True)
        LOG.info("Loaded type driver names: %s", self.names())
        self._register_types()
        self._check_tenant_network_types(cfg.CONF.ml2.tenant_network_types)
        self._check_external_network_type(cfg.CONF.ml2.external_network_type)

    def _register_types(self):
        for ext in self:
            network_type = ext.obj.get_type()
            if network_type in self.drivers:
                LOG.error("Type driver '%(new_driver)s' ignored because"
                          " type driver '%(old_driver)s' is already"
                          " registered for type '%(type)s'",
                          {'new_driver': ext.name,
                           'old_driver': self.drivers[network_type].name,
                           'type': network_type})
            else:
                self.drivers[network_type] = ext
        LOG.info("Registered types: %s", self.drivers.keys())

    def _check_tenant_network_types(self, types):
        self.tenant_network_types = []
        for network_type in types:
            if network_type in self.drivers:
                self.tenant_network_types.append(network_type)
            else:
                LOG.error("No type driver for tenant network_type: %s. "
                          "Service terminated!", network_type)
                raise SystemExit(1)
        LOG.info("Tenant network_types: %s", self.tenant_network_types)

    def _check_external_network_type(self, ext_network_type):
        if ext_network_type and ext_network_type not in self.drivers:
            LOG.error("No type driver for external network_type: %s. "
                      "Service terminated!", ext_network_type)
            raise SystemExit(1)

    def _process_provider_segment(self, segment):
        (network_type, physical_network,
         segmentation_id) = (self._get_attribute(segment, attr)
                             for attr in provider.ATTRIBUTES)

        if validators.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            self.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _process_provider_create(self, network):
        if any(validators.is_attr_set(network.get(attr))
               for attr in provider.ATTRIBUTES):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)):
                raise mpnet_exc.SegmentsSetInConjunctionWithProviders()
            segment = self._get_provider_segment(network)
            return [self._process_provider_segment(segment)]
        elif validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)):
            segments = [self._process_provider_segment(s)
                        for s in network[mpnet_apidef.SEGMENTS]]
            mpnet_apidef.check_duplicate_segments(
                segments, self.is_partial_segment)
            return segments

    def _get_provider_segment(self, network):
        # TODO(manishg): Placeholder method
        # Code intended for operating on a provider segment should use
        # this method to extract the segment, even though currently the
        # segment attributes are part of the network dictionary. In the
        # future, network and segment information will be decoupled and
        # here we will do the job of extracting the segment information.
        return network

    def _get_attribute(self, attrs, key):
        value = attrs.get(key)
        if value is constants.ATTR_NOT_SPECIFIED:
            value = None
        return value

    def extend_network_dict_provider(self, context, network):
        # this method is left for backward compat even though it would be
        # easy to change the callers in tree to use the bulk function
        return self.extend_networks_dict_provider(context, [network])

    def extend_networks_dict_provider(self, context, networks):
        ids = [network['id'] for network in networks]
        net_segments = segments_db.get_networks_segments(context, ids)
        for network in networks:
            segments = net_segments[network['id']]
            self.extend_network_with_provider_segments(network, segments)

    def extend_network_with_provider_segments(self, network, segments):
        if not segments:
            LOG.debug("Network %s has no segments", network['id'])
            for attr in provider.ATTRIBUTES:
                network[attr] = None
        elif len(segments) > 1:
            network[mpnet_apidef.SEGMENTS] = [
                {provider.NETWORK_TYPE: segment[api.NETWORK_TYPE],
                 provider.PHYSICAL_NETWORK: segment[api.PHYSICAL_NETWORK],
                 provider.SEGMENTATION_ID: segment[api.SEGMENTATION_ID]}
                for segment in segments]
        else:
            segment = segments[0]
            network[provider.NETWORK_TYPE] = segment[api.NETWORK_TYPE]
            network[provider.PHYSICAL_NETWORK] = segment[
                api.PHYSICAL_NETWORK]
            network[provider.SEGMENTATION_ID] = segment[
                api.SEGMENTATION_ID]

    @staticmethod
    def pop_segments_from_network(network):
        multiple_segments = network.pop(mpnet_apidef.SEGMENTS, [])
        if multiple_segments:
            network_segments = multiple_segments
        else:
            network_segments = [
                {provider_key: network.pop(provider_key)
                 for provider_key in provider.ATTRIBUTES}]

        return (
            [{api.NETWORK_TYPE: network_segment[provider.NETWORK_TYPE],
              api.PHYSICAL_NETWORK: network_segment[provider.PHYSICAL_NETWORK],
              api.SEGMENTATION_ID: network_segment[provider.SEGMENTATION_ID]}
             for network_segment in network_segments])

    def initialize(self):
        for network_type, driver in self.drivers.items():
            LOG.info("Initializing driver for type '%s'", network_type)
            driver.obj.initialize()

    def initialize_network_segment_range_support(self):
        for network_type, driver in self.drivers.items():
            if network_type in constants.NETWORK_SEGMENT_RANGE_TYPES:
                LOG.info("Initializing driver network segment range support "
                         "for type '%s'", network_type)
                driver.obj.initialize_network_segment_range_support()

    def _add_network_segment(self, context, network_id, segment,
                             segment_index=0):
        segments_db.add_network_segment(
            context, network_id, segment, segment_index)

    def _update_network_segment(self, context, network_id, segmentation_id):
        segments_db.update_network_segment(
            context, network_id, segmentation_id)

    def create_network_segments(self, context, network, tenant_id):
        """Call type drivers to create network segments."""
        segments = self._process_provider_create(network)
        filters = {'project_id': tenant_id}
        with db_api.CONTEXT_WRITER.using(context):
            network_id = network['id']
            if segments:
                for segment_index, segment in enumerate(segments):
                    segment = self.reserve_provider_segment(
                        context, segment, filters=filters)
                    self._add_network_segment(context, network_id, segment,
                                              segment_index)
            elif (cfg.CONF.ml2.external_network_type and
                  self._get_attribute(network, extnet_apidef.EXTERNAL)):
                segment = self._allocate_ext_net_segment(
                    context, filters=filters)
                self._add_network_segment(context, network_id, segment)
            else:
                segment = self._allocate_tenant_net_segment(
                    context, filters=filters)
                self._add_network_segment(context, network_id, segment)

    def update_network_segment(self, context, network, net_data, segment):
        """Call type drivers to update a network segment.

        Update operation is currently only supported for VLAN type segments,
        and only the SEGMENTATION_ID field can be changed.
        """
        project_id = network['project_id']
        segmentation_id = net_data.get(provider.SEGMENTATION_ID)
        network_type = segment[api.NETWORK_TYPE]
        if network_type != constants.TYPE_VLAN:
            msg = (_('Only VLAN type networks can be updated.'))
            raise exc.InvalidInput(error_message=msg)
        if not segmentation_id:
            msg = (_('Only %s field can be updated in VLAN type networks') %
                   api.SEGMENTATION_ID)
            raise exc.InvalidInput(error_message=msg)

        new_segment = {api.NETWORK_TYPE: segment[api.NETWORK_TYPE],
                       api.PHYSICAL_NETWORK: segment[api.PHYSICAL_NETWORK],
                       api.SEGMENTATION_ID: segmentation_id}
        self.validate_provider_segment(new_segment)
        self.reserve_provider_segment(context, new_segment,
                                      filters={'project_id': project_id})
        self._update_network_segment(context, segment['id'], segmentation_id)
        self.release_network_segment(context, segment)

    def reserve_network_segment(self, context, segment_data):
        """Call type drivers to reserve a network segment."""
        # Validate the data of segment
        if not validators.is_attr_set(segment_data[api.NETWORK_TYPE]):
            msg = _("network_type required")
            raise exc.InvalidInput(error_message=msg)

        net_type = self._get_attribute(segment_data, api.NETWORK_TYPE)
        phys_net = self._get_attribute(segment_data, api.PHYSICAL_NETWORK)
        seg_id = self._get_attribute(segment_data, api.SEGMENTATION_ID)
        segment = {api.NETWORK_TYPE: net_type,
                   api.PHYSICAL_NETWORK: phys_net,
                   api.SEGMENTATION_ID: seg_id}

        self.validate_provider_segment(segment)

        # Reserve segment in type driver
        return self.reserve_provider_segment(context, segment)

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

    def reserve_provider_segment(self, context, segment, filters=None):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        if isinstance(driver.obj, api.TypeDriver):
            return driver.obj.reserve_provider_segment(context.session,
                                                       segment, filters)
        else:
            return driver.obj.reserve_provider_segment(context,
                                                       segment, filters)

    def _allocate_segment(self, context, network_type, filters=None):
        driver = self.drivers.get(network_type)
        if isinstance(driver.obj, api.TypeDriver):
            return driver.obj.allocate_tenant_segment(context.session, filters)
        else:
            return driver.obj.allocate_tenant_segment(context, filters)

    def _allocate_tenant_net_segment(self, context, filters=None):
        for network_type in self.tenant_network_types:
            segment = self._allocate_segment(context, network_type, filters)
            if segment:
                return segment
        raise exc.NoNetworkAvailable()

    def _allocate_ext_net_segment(self, context, filters=None):
        network_type = cfg.CONF.ml2.external_network_type
        segment = self._allocate_segment(context, network_type, filters)
        if segment:
            return segment
        raise exc.NoNetworkAvailable()

    def release_network_segments(self, context, network_id):
        segments = segments_db.get_network_segments(context, network_id,
                                                    filter_dynamic=None)

        for segment in segments:
            self.release_network_segment(context, segment)

    def release_network_segment(self, context, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        if driver:
            if isinstance(driver.obj, api.TypeDriver):
                driver.obj.release_segment(context.session, segment)
            else:
                driver.obj.release_segment(context, segment)
        else:
            LOG.error("Failed to release segment '%s' because "
                      "network type is not supported.", segment)

    @db_api.retry_if_session_inactive()
    def allocate_dynamic_segment(self, context, network_id, segment):
        """Allocate a dynamic segment using a partial or full segment dict."""
        dynamic_segment = segments_db.get_dynamic_segment(
            context, network_id, segment.get(api.PHYSICAL_NETWORK),
            segment.get(api.SEGMENTATION_ID))

        if dynamic_segment:
            return dynamic_segment

        with db_api.CONTEXT_WRITER.using(context):
            driver = self.drivers.get(segment.get(api.NETWORK_TYPE))
            if isinstance(driver.obj, api.TypeDriver):
                dynamic_segment = driver.obj.reserve_provider_segment(
                    context.session, segment)
            else:
                dynamic_segment = driver.obj.reserve_provider_segment(
                    context, segment)
            segments_db.add_network_segment(context, network_id,
                                            dynamic_segment,
                                            is_dynamic=True)
        return dynamic_segment

    @db_api.retry_if_session_inactive()
    def release_dynamic_segment(self, context, segment_id):
        """Delete a dynamic segment."""
        segment = segments_db.get_segment_by_id(context, segment_id)
        if segment:
            with db_api.CONTEXT_WRITER.using(context):
                driver = self.drivers.get(segment.get(api.NETWORK_TYPE))
                if driver:
                    if isinstance(driver.obj, api.TypeDriver):
                        driver.obj.release_segment(context.session, segment)
                    else:
                        driver.obj.release_segment(context, segment)
                    segments_db.delete_network_segment(context, segment_id)
                else:
                    LOG.error("Failed to release segment '%s' because "
                              "network type is not supported.", segment)
        else:
            LOG.debug("No segment found with id %(segment_id)s", segment_id)

    def update_network_segment_range_allocations(self, network_type):
        driver = self.drivers.get(network_type)
        driver.obj.update_network_segment_range_allocations()

    def network_type_supported(self, network_type):
        return bool(network_type in self.drivers)


class MechanismManager(stevedore.named.NamedExtensionManager):
    """Manage networking mechanisms using drivers."""

    def __init__(self):
        # Registered mechanism drivers, keyed by name.
        self.mech_drivers = {}
        # Ordered list of mechanism drivers, defining
        # the order in which the drivers are called.
        self.ordered_mech_drivers = []

        LOG.info("Configured mechanism driver names: %s",
                 cfg.CONF.ml2.mechanism_drivers)
        super(MechanismManager, self).__init__(
            'neutron.ml2.mechanism_drivers',
            cfg.CONF.ml2.mechanism_drivers,
            invoke_on_load=True,
            name_order=True,
            on_missing_entrypoints_callback=self._driver_not_found,
            on_load_failure_callback=self._driver_not_loaded
        )
        LOG.info("Loaded mechanism driver names: %s", self.names())
        self._register_mechanisms()
        self.host_filtering_supported = self.is_host_filtering_supported()
        if not self.host_filtering_supported:
            LOG.info("No mechanism drivers provide segment reachability "
                     "information for agent scheduling.")

    def _driver_not_found(self, names):
        msg = (_("The following mechanism drivers were not found: %s")
               % names)
        LOG.critical(msg)
        raise SystemExit(msg)

    def _driver_not_loaded(self, manager, entrypoint, exception):
        LOG.critical("The '%(entrypoint)s' entrypoint could not be"
                     " loaded for the following reason: '%(reason)s'.",
                     {'entrypoint': entrypoint,
                      'reason': exception})
        raise SystemExit(str(exception))

    def _register_mechanisms(self):
        """Register all mechanism drivers.

        This method should only be called once in the MechanismManager
        constructor.
        """
        for ext in self:
            self.mech_drivers[ext.name] = ext
            self.ordered_mech_drivers.append(ext)
        LOG.info("Registered mechanism drivers: %s",
                 [driver.name for driver in self.ordered_mech_drivers])

    def initialize(self):
        for driver in self.ordered_mech_drivers:
            LOG.info("Initializing mechanism driver '%s'", driver.name)
            driver.obj.initialize()

    def _check_vlan_transparency(self, context):
        """Helper method for checking vlan transparecncy support.

        :param context: context parameter to pass to each method call
        :raises: neutron_lib.exceptions.vlantransparent.
        VlanTransparencyDriverError if any mechanism driver doesn't
        support vlan transparency.
        """
        if context.current.get('vlan_transparent'):
            for driver in self.ordered_mech_drivers:
                if not driver.obj.check_vlan_transparency(context):
                    raise vlan_exc.VlanTransparencyDriverError()

    def _call_on_drivers(self, method_name, context,
                         continue_on_failure=False, raise_db_retriable=False):
        """Helper method for calling a method across all mechanism drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param continue_on_failure: whether or not to continue to call
        all mechanism drivers once one has raised an exception
        :param raise_db_retriable: whether or not to treat retriable db
        exception by mechanism drivers to propagate up to upper layer so
        that upper layer can handle it or error in ML2 player
        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver call fails. or DB retriable error when
        raise_db_retriable=False. See neutron_lib.db.api.is_retriable for
        what db exception is retriable
        """
        errors = []
        for driver in self.ordered_mech_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception as e:
                if raise_db_retriable and db_api.is_retriable(e):
                    with excutils.save_and_reraise_exception():
                        LOG.debug("DB exception raised by Mechanism driver "
                                  "'%(name)s' in %(method)s",
                                  {'name': driver.name, 'method': method_name},
                                  exc_info=e)
                LOG.exception(
                    "Mechanism driver '%(name)s' failed in %(method)s",
                    {'name': driver.name, 'method': method_name}
                )
                errors.append(e)
                if not continue_on_failure:
                    break
        if errors:
            raise ml2_exc.MechanismDriverError(
                method=method_name,
                errors=errors
            )

    def create_network_precommit(self, context):
        """Notify all mechanism drivers during network creation.

        :raises: DB retriable error if create_network_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._check_vlan_transparency(context)
        self._call_on_drivers("create_network_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if update_network_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_network_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if delete_network_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_network_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_network_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if create_subnet_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_subnet_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if update_subnet_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_subnet_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if delete_subnet_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_subnet_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_subnet_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if create_port_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_port_precommit", context,
                              raise_db_retriable=True)

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

        :raises: DB retriable error if update_port_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("update_port_precommit", context,
                              raise_db_retriable=True)

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

        :raises:DB retriable error if delete_port_precommit raises them
        See neutron_lib.db.api.is_retriable for what db exception is retriable
        or neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver delete_port_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_port_precommit", context,
                              raise_db_retriable=True)

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
            LOG.error("Failed to bind port %(port)s on host %(host)s "
                      "for vnic_type %(vnic_type)s using segments "
                      "%(segments)s",
                      {'port': context.current['id'],
                       'host': context.host,
                       'vnic_type': binding.vnic_type,
                       'segments': context.network.network_segments})

    def _bind_port_level(self, context, level, segments_to_bind,
                         drivers=None, redoing_bottom=False):
        if drivers is None:
            drivers = self.ordered_mech_drivers

        binding = context._binding
        port_id = context.current['id']
        LOG.debug("Attempting to bind port %(port)s by drivers %(drivers)s "
                  "on host %(host)s at level %(level)s using "
                  "segments %(segments)s",
                  {'port': port_id,
                   'drivers': ','.join([driver.name for driver in drivers]),
                   'host': context.host,
                   'level': level,
                   'segments': segments_to_bind})

        if level == MAX_BINDING_LEVELS:
            LOG.error("Exceeded maximum binding levels attempting to bind "
                      "port %(port)s on host %(host)s",
                      {'port': context.current['id'],
                       'host': context.host})
            return False

        drivers = self._check_drivers_connectivity(drivers, context)
        if not drivers:
            LOG.error("Port %(port)s does not have an IP address assigned and "
                      "there are no driver with 'connectivity' = 'l2'. The "
                      "port cannot be bound.",
                      {'port': context.current['id']})
            return False

        for driver in drivers:
            if not self._check_driver_to_bind(driver, segments_to_bind,
                                              context._binding_levels):
                continue

            try:
                context._prepare_to_bind(segments_to_bind)
                driver.obj.bind_port(context)
                segment = context._new_bound_segment
                if segment:
                    pbl_obj = ports.PortBindingLevel(
                        context.plugin_context,
                        port_id=port_id,
                        host=context.host,
                        level=level,
                        driver=driver.name,
                        segment_id=segment
                    )
                    context._push_binding_level(pbl_obj)
                    next_segments = context._next_segments_to_bind
                    if next_segments:
                        # Continue binding another level.
                        if self._bind_port_level(context, level + 1,
                                                 next_segments):
                            return True
                        else:
                            LOG.warning("Failed to bind port %(port)s on "
                                        "host %(host)s at level %(lvl)s",
                                        {'port': context.current['id'],
                                         'host': context.host,
                                         'lvl': level + 1})
                            context._pop_binding_level()
                    else:
                        # NOTE(bence romsics): Consider: "In case of
                        # hierarchical port binding binding_profile.allocation
                        # [decided and sent by Placement and Nova]
                        # is meant to drive the binding only on the binding
                        # level that represents the closest physical interface
                        # to the nova server." Link to spec:
                        #
                        # https://review.opendev.org/#/c/508149/14/specs\
                        #        /rocky/minimum-bandwidth-\
                        #        allocation-placement-api.rst@582
                        #
                        # But we cannot tell if a binding level is
                        # the bottom binding level before set_binding()
                        # gets called, and that's already too late. So we
                        # must undo the last binding after set_binding()
                        # was called and redo the last level trying to
                        # bind only with one driver as inferred from
                        # the allocation. In order to undo the binding
                        # here we must also assume that each driver's
                        # bind_port() implementation is side effect free
                        # beyond calling set_binding().
                        #
                        # Also please note that technically we allow for
                        # a redo to call continue_binding() instead of
                        # set_binding() and by that turn what was supposed
                        # to be the bottom level into a non-bottom binding
                        # level. A thorough discussion is recommended if
                        # you think of taking advantage of this.
                        #
                        # Also if we find use cases requiring
                        # diamond-shaped selections of drivers on different
                        # levels (eg. driverA and driverB can be both
                        # a valid choice on level 0, but on level 1 both
                        # previous choice leads to driverC) then we need
                        # to restrict segment selection too based on
                        # traits of the allocated resource provider on
                        # the top binding_level (==0).
                        if (context.current['binding:profile'] is not None and
                                context.current[
                                    'binding:profile'].get('allocation') and
                                not redoing_bottom):
                            LOG.debug(
                                "Undo bottom bound level and redo it "
                                "according to binding_profile.allocation: %s",
                                context.current['binding:profile'][
                                    'allocation'])
                            context._pop_binding_level()
                            context._unset_binding()
                            return self._bind_port_level(
                                context, level, segments_to_bind,
                                drivers=[self._infer_driver_from_allocation(
                                    context)],
                                redoing_bottom=True)

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
                LOG.exception("Mechanism driver %s failed in "
                              "bind_port",
                              driver.name)

    def _infer_driver_from_allocation(self, context):
        """Choose mechanism driver as implied by allocation in placement.

        :param context: PortContext instance describing the port
        :returns: a single MechanismDriver instance

        Ports allocated to a resource provider (ie. a physical network
        interface) in Placement have the UUID of the provider in their
        binding:profile.allocation. The choice of a physical network
        interface (as recorded in the allocation) implies a choice of
        mechanism driver too. When an allocation was received we expect
        exactly one mechanism driver to be responsible for that physical
        network interface resource provider.
        """

        drivers = []
        for driver in self.ordered_mech_drivers:
            if driver.obj.responsible_for_ports_allocation(context):
                drivers.append(driver)

        allocation = context.current['binding:profile']['allocation']

        if len(drivers) == 0:
            LOG.error("Failed to bind port %(port)s on host "
                      "%(host)s allocated on resource providers: "
                      "%(rsc_providers)s, because no mechanism driver "
                      "reports being responsible",
                      {'port': context.current['id'],
                       'host': context.host,
                       'rsc_providers': ','.join(allocation.values())})
            raise place_exc.UnknownResourceProvider(
                rsc_provider=','.join(allocation.values()))

        if len(drivers) >= 2:
            raise place_exc.AmbiguousResponsibilityForResourceProvider(
                rsc_provider=','.join(allocation.values()),
                drivers=','.join([driver.name for driver in drivers]))

        # NOTE(bence romsics): The error conditions for raising either
        # UnknownResourceProvider or AmbiguousResponsibilityForResourceProvider
        # are pretty static therefore the usual 10-times-retry of a binding
        # failure could easily be unnecessary in those cases. However at this
        # point special handling of these exceptions in the binding retry loop
        # seems like premature optimization to me since these exceptions are
        # always a sign of a misconfigured neutron deployment.

        LOG.debug("Restricting possible bindings of port %(port)s "
                  "(as inferred from placement allocation) to "
                  "mechanism driver '%(driver)s'",
                  {'port': context.current['id'],
                   'driver': drivers[0].name})

        return drivers[0]

    def is_host_filtering_supported(self):
        return all(driver.obj.is_host_filtering_supported()
                   for driver in self.ordered_mech_drivers)

    def filter_hosts_with_segment_access(
            self, context, segments, candidate_hosts, agent_getter):
        """Filter hosts with access to at least one segment.

        :returns: a subset of candidate_hosts.

        This method returns all hosts from candidate_hosts with access to a
        segment according to at least one driver.
        """
        candidate_hosts = set(candidate_hosts)
        if not self.host_filtering_supported:
            return candidate_hosts

        hosts_with_access = set()
        for driver in self.ordered_mech_drivers:
            hosts = driver.obj.filter_hosts_with_segment_access(
                context, segments, candidate_hosts, agent_getter)
            hosts_with_access |= hosts
            candidate_hosts -= hosts
            if not candidate_hosts:
                break
        return hosts_with_access

    def _check_driver_to_bind(self, driver, segments_to_bind, binding_levels):
        # To prevent a possible binding loop, don't try to bind with
        # this driver if the same driver has already bound at a higher
        # level to one of the segments we are currently trying to
        # bind. Note that it is OK for the same driver to bind at
        # multiple levels using different segments.
        segment_ids_to_bind = {s[api.ID]
                               for s in segments_to_bind}
        for level in binding_levels:
            if (level.driver == driver.name and
                    level.segment_id in segment_ids_to_bind):
                LOG.debug("segment %(segment)s is already bound "
                          "by driver %(driver)s",
                          {"segment": level.segment_id,
                           "driver": level.driver})
                return False
        return True

    def _check_drivers_connectivity(self, drivers, port_context):
        """If port does not have an IP address, driver connectivity must be l2

        A port without an IP address can be bound only to a mech driver with
        "connectivity" = "l2". "legacy" or "l3" (e.g.: Calico) drivers cannot
        have a port bound without an IP allocated.
        """
        if port_context.current.get('fixed_ips'):
            return drivers

        return [d for d in drivers if
                d.obj.connectivity == portbindings.CONNECTIVITY_L2]

    def get_workers(self):
        workers = []
        for driver in self.ordered_mech_drivers:
            workers += driver.obj.get_workers()
        return workers


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extension drivers using drivers."""

    def __init__(self):
        # Ordered list of extension drivers, defining
        # the order in which the drivers are called.
        self.ordered_ext_drivers = []

        LOG.info("Configured extension driver names: %s",
                 cfg.CONF.ml2.extension_drivers)
        super(ExtensionManager, self).__init__('neutron.ml2.extension_drivers',
                                               cfg.CONF.ml2.extension_drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info("Loaded extension driver names: %s", self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        for ext in self:
            self.ordered_ext_drivers.append(ext)
        LOG.info("Registered extension drivers: %s",
                 [driver.name for driver in self.ordered_ext_drivers])

    def initialize(self):
        # Initialize each driver in the list.
        for driver in self.ordered_ext_drivers:
            LOG.info("Initializing extension driver '%s'", driver.name)
            driver.obj.initialize()

    def extension_aliases(self):
        exts = []
        for driver in self.ordered_ext_drivers:
            aliases = driver.obj.extension_aliases
            for alias in aliases:
                if not alias:
                    continue
                exts.append(alias)
                LOG.info("Got %(alias)s extension from driver '%(drv)s'",
                         {'alias': alias, 'drv': driver.name})
        return exts

    def _call_on_ext_drivers(self, method_name, plugin_context, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(plugin_context, data, result)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.info("Extension driver '%(name)s' failed in "
                             "%(method)s",
                             {'name': driver.name, 'method': method_name})

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

    def _call_on_dict_driver(self, method_name, session, base_model, result):
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(session, base_model, result)
            except Exception:
                LOG.exception("Extension driver '%(name)s' failed in "
                              "%(method)s",
                              {'name': driver.name, 'method': method_name})
                raise ml2_exc.ExtensionDriverError(driver=driver.name)

    def extend_network_dict(self, session, base_model, result):
        """Notify all extension drivers to extend network dictionary."""
        self._call_on_dict_driver("extend_network_dict", session, base_model,
                                  result)

    def extend_subnet_dict(self, session, base_model, result):
        """Notify all extension drivers to extend subnet dictionary."""
        self._call_on_dict_driver("extend_subnet_dict", session, base_model,
                                  result)

    def extend_port_dict(self, session, base_model, result):
        """Notify all extension drivers to extend port dictionary."""
        self._call_on_dict_driver("extend_port_dict", session, base_model,
                                  result)
