# Copyright (c) 2017 Fujitsu Limited
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.services.logapi import constants as log_const
from oslo_log import log as logging

from neutron.services.logapi.rpc import server as server_rpc

LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class DriverBase(object):

    def __init__(self, name, vif_types, vnic_types,
                 supported_logging_types, requires_rpc=False):
        """Instantiate a log driver.

        :param name: driver name.
        :param vif_types: list of interfaces (VIFs) supported.
        :param vnic_types: list of vnic types supported.
        :param supported_logging_types: list of supported logging types.
        :param requires_rpc: indicates if this driver expects rpc sever
               to notify or callback
        """

        self.name = name
        self.vif_types = vif_types
        self.vnic_types = vnic_types
        self.supported_logging_types = supported_logging_types
        self.requires_rpc = requires_rpc

    # The log driver should advertise itself as supported driver by calling
    # register_driver() on the LoggingServiceDriverManager. Therefore,
    # logging plugin can discover which resources types are supported by
    # the log driver.
    @registry.receives(log_const.LOGGING_PLUGIN, [events.AFTER_INIT])
    def _register(self, resource, event, trigger, payload=None):
        # pylint: disable=using-constant-test
        if self.is_loaded:
            # trigger is the LoggingServiceDriverManager
            trigger.register_driver(self)

    def register_rpc_methods(self, resource_type, rpc_methods):
        server_rpc.register_rpc_methods(resource_type, rpc_methods)

    def is_loaded(self):
        """True if the driver is active for the Neutron Server.

        Implement this method to determine if your driver is actively
        configured for this Neutron Server deployment.
        """
        return True

    def is_vif_type_compatible(self, vif_type):
        """True if the driver is compatible with the VIF type."""
        return vif_type in self.vif_types

    def is_vnic_compatible(self, vnic_type):
        """True if the driver is compatible with the specific VNIC type."""
        return vnic_type in self.vnic_types

    def is_logging_type_supported(self, log_type):
        supported = log_type in self.supported_logging_types
        if not supported:
            LOG.debug("logging type %(log_type)s is not supported by "
                      "%(driver_name)s",
                      {'log_type': log_type,
                       'driver_name': self.name})
        return supported

    def create_log(self, context, log_obj):
        """Create a log_obj invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary with a specific log object.

        :param context: current running context information
        :param log_obj: a log objects being created

        """

    def create_log_precommit(self, context, log_obj):
        """Create a log_obj precommit.

        This method can be implemented by the specific driver subclass
        to handle the precommit event of a log_object that is being created.

        :param context: current running context information
        :param log_obj: a log object being created
        """

    def update_log(self, context, log_obj):
        """Update a log_obj invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary with a specific log object.

        :param context: current running context information
        :param log_obj: a log object being updated

        """

    def update_log_precommit(self, context, log_obj):
        """Update a log_obj precommit.

        This method can be implemented by the specific driver subclass
        to handle update precommit event of a log_object that is being updated.

        :param context: current running context information
        :param log_obj: a log_object being updated.
        """

    def delete_log(self, context, log_obj):
        """Delete a log_obj invocation.

        This method can be implemented by the specific driver subclass
        to delete the backend where necessary with a specific log object.

        :param context: current running context information
        :param log_obj: a log_object being deleted

        """

    def delete_log_precommit(self, context, log_obj):
        """Delete a log_obj precommit.

        This method can be implemented by the specific driver subclass
        to handle delete precommit event of a log_object that is being deleted.

        :param context: current running context information
        :param log_obj: a log_object being deleted
        """

    def resource_update(self, context, log_objs):
        """Tell the agent when resources related to log_objects are
        being updated

        :param context: current running context information
        :param log_objs: a list of log_objects, whose related resources are
                         being updated.
        """
