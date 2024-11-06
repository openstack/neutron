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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils
from oslo_log import log as logging

from neutron.services.logapi.common import exceptions as log_exc

LOG = logging.getLogger(__name__)

SKIPPED_VIF_TYPES = [
    portbindings.VIF_TYPE_UNBOUND,
    portbindings.VIF_TYPE_BINDING_FAILED,
]


def _validate_vnic_type(driver, vnic_type, port_id):
    if driver.is_vnic_compatible(vnic_type):
        return True
    LOG.debug("vnic_type %(vnic_type)s of port %(port_id)s "
              "is not compatible with logging driver %(driver)s",
              {'vnic_type': vnic_type,
               'port_id': port_id,
               'driver': driver.name})
    return False


def _validate_vif_type(driver, vif_type, port_id):
    if driver.is_vif_type_compatible(vif_type):
        return True
    LOG.debug("vif_type %(vif_type)s of port %(port_id)s "
              "is not compatible with logging driver %(driver)s",
              {'vif_type': vif_type,
               'port_id': port_id,
               'driver': driver.name})
    return False


def validate_log_type_for_port(log_type, port):
    """Validate a specific logging type on a specific port

    This method checks whether or not existing a log_driver which supports for
    the logging type on the port.

    :param log_type: a logging type (e.g security_group)
    :param port: a port object

    """

    log_plugin = directory.get_plugin(alias=plugin_const.LOG_API)
    drivers = log_plugin.driver_manager.drivers
    port_binding = utils.get_port_binding_by_status_and_host(
        port.bindings, constants.ACTIVE, raise_if_not_found=True,
        port_id=port['id'])
    for driver in drivers:
        vif_type = port_binding.vif_type
        if vif_type not in SKIPPED_VIF_TYPES:
            if not _validate_vif_type(driver, vif_type, port['id']):
                continue
        else:
            vnic_type = port_binding.vnic_type
            if not _validate_vnic_type(driver, vnic_type, port['id']):
                continue

        if driver.is_logging_type_supported(log_type):
            return True
    return False


class ResourceValidateRequest:

    _instance = None

    def __init__(self):
        self.validate_methods = {}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def validate_methods_map(self):
        return self.validate_methods

    def validate_request(self, context, log_data):
        """Validate request

        This method will get validated method according to resource_type. An
        InvalidLogResourceType exception will be raised if there is no logging
        driver that supports resource_type as logging resource. In addition,
        a ValidatedMethodNotFound exception will be raised if a validate method
        was not registered for resource_type.
        """

        resource_type = log_data.get('resource_type')
        log_plugin = directory.get_plugin(alias=plugin_const.LOG_API)
        supported_logging_types = log_plugin.supported_logging_types

        if resource_type not in supported_logging_types:
            raise log_exc.InvalidLogResourceType(resource_type=resource_type)

        method = self.get_validated_method(resource_type)
        method(context, log_data)

    def get_validated_method(self, resource_type):
        """Get the validated method for resource_type"""

        method = self.validate_methods[resource_type]
        if not method:
            raise log_exc.ValidatedMethodNotFound(resource_type=resource_type)
        return method

    @classmethod
    def register(cls, resource_type):
        """This is intended to be used as a decorator to register a validated
        method for resource_type.
        """
        def func_wrap(func):
            cls.get_instance().validate_methods[resource_type] = func
            return func
        return func_wrap
