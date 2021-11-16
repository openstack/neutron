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
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants as lib_constants
from neutron_lib import exceptions
from neutron_lib.plugins import utils
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.callbacks.producer import registry as rpc_registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects.qos import policy as policy_object


LOG = logging.getLogger(__name__)


SKIPPED_VIF_TYPES = [
    portbindings.VIF_TYPE_UNBOUND,
    portbindings.VIF_TYPE_BINDING_FAILED
]


class QosServiceDriverManager(object):

    def __init__(self):
        self._drivers = []
        self.rpc_notifications_required = False
        rpc_registry.provide(self._get_qos_policy_cb, resources.QOS_POLICY)
        # notify any registered QoS driver that we're ready, those will
        # call the driver manager back with register_driver if they
        # are enabled
        registry.publish(qos_consts.QOS_PLUGIN, events.AFTER_INIT, self)

        if self.rpc_notifications_required:
            self.push_api = resources_rpc.ResourcesPushRpcApi()

    @staticmethod
    def _get_qos_policy_cb(resource, policy_id, **kwargs):
        context = kwargs.get('context')
        if context is None:
            LOG.warning(
                'Received %(resource)s %(policy_id)s without context',
                {'resource': resource, 'policy_id': policy_id})
            return

        policy = policy_object.QosPolicy.get_object(context, id=policy_id)
        return policy

    @staticmethod
    def _validate_vnic_type(driver, vnic_type, port_id):
        if driver.is_vnic_compatible(vnic_type):
            return True
        LOG.debug("vnic_type %(vnic_type)s of port %(port_id)s "
                  "is not compatible with QoS driver %(driver)s",
                  {'vnic_type': vnic_type,
                   'port_id': port_id,
                   'driver': driver.name})
        return False

    @staticmethod
    def _validate_vif_type(driver, vif_type, port_id):
        if driver.is_vif_type_compatible(vif_type):
            return True
        LOG.debug("vif_type %(vif_type)s of port %(port_id)s "
                  "is not compatible with QoS driver %(driver)s",
                  {'vif_type': vif_type,
                   'port_id': port_id,
                   'driver': driver.name})
        return False

    @staticmethod
    def _parse_parameter_values(parameter_values):
        validator, possible_values = list(parameter_values.items())[0]
        if validator == 'type:range':
            parameter_values = {
                "start": possible_values[0],
                "end": possible_values[1]
            }
            parameter_type = lib_constants.VALUES_TYPE_RANGE
        elif validator == 'type:values':
            parameter_values = possible_values
            parameter_type = lib_constants.VALUES_TYPE_CHOICES
        return parameter_values, parameter_type

    def call(self, method_name, *args, **kwargs):
        """Helper method for calling a method across all extension drivers."""
        exc_list = []
        for driver in self._drivers:
            try:
                getattr(driver, method_name)(*args, **kwargs)
            except Exception as exc:
                exception_msg = ("Extension driver '%(name)s' failed in "
                                 "%(method)s")
                exception_data = {'name': driver.name, 'method': method_name}
                LOG.exception(exception_msg, exception_data)
                exc_list.append(exc)

        if exc_list:
            raise exceptions.DriverCallError(exc_list=exc_list)

        if self.rpc_notifications_required:
            context = kwargs.get('context') or args[0]
            policy_obj = kwargs.get('policy_obj') or args[1]

            # we don't push create_policy events since policies are empty
            # on creation, they only become of any use when rules get
            # attached to them.
            if method_name == qos_consts.UPDATE_POLICY:
                self.push_api.push(context, [policy_obj], rpc_events.UPDATED)

            elif method_name == qos_consts.DELETE_POLICY:
                self.push_api.push(context, [policy_obj], rpc_events.DELETED)

    def register_driver(self, driver):
        """Register driver with qos plugin.

        This method is called from drivers on INIT event.
        """
        self._drivers.append(driver)
        self.rpc_notifications_required |= driver.requires_rpc_notifications

    def validate_rule_for_port(self, context, rule, port):
        port_binding = utils.get_port_binding_by_status_and_host(
            port.bindings, lib_constants.ACTIVE, raise_if_not_found=True,
            port_id=port['id'])
        for driver in self._drivers:
            vif_type = port_binding.vif_type
            if vif_type not in SKIPPED_VIF_TYPES:
                if not self._validate_vif_type(driver, vif_type, port['id']):
                    continue
            else:
                vnic_type = port_binding.vnic_type
                if not self._validate_vnic_type(driver, vnic_type, port['id']):
                    continue

            if (driver.is_rule_supported(rule) and
                    driver.validate_rule_for_port(context, rule, port)):
                return True

        return False

    def validate_rule_for_network(self, context, rule, network_id):
        for driver in self._drivers:
            if (driver.is_rule_supported(rule) and
                    driver.validate_rule_for_network(context, rule,
                                                     network_id)):
                return True

        return False

    @property
    def supported_rule_types(self):
        if not self._drivers:
            return []

        rule_types = set(qos_consts.VALID_RULE_TYPES)

        # Recalculate on every call to allow drivers determine supported rule
        # types dynamically
        for driver in self._drivers:
            new_rule_types = rule_types & set(driver.supported_rules)
            dropped_rule_types = rule_types - new_rule_types
            if dropped_rule_types:
                LOG.debug("%(rule_types)s rule types disabled "
                          "because enabled %(driver)s does not support them",
                          {'rule_types': ', '.join(dropped_rule_types),
                           'driver': driver.name})
            rule_types = new_rule_types

        LOG.debug("Supported QoS rule types "
                  "(common subset for all loaded QoS drivers): %s", rule_types)
        return rule_types

    def supported_rule_type_details(self, rule_type_name):
        if not self._drivers:
            return []

        rule_type_drivers = []
        for driver in self._drivers:
            if rule_type_name in driver.supported_rules:
                supported_parameters = []
                rule_parameters = driver.supported_rules.get(rule_type_name)
                for name, values in rule_parameters.items():
                    parameter_values, parameter_type = (
                        self._parse_parameter_values(values))
                    supported_parameters.append({
                        "parameter_name": name,
                        "parameter_values": parameter_values,
                        "parameter_type": parameter_type
                    })
                rule_type_drivers.append({
                    "name": driver.name,
                    "supported_parameters": supported_parameters
                })

        return rule_type_drivers
