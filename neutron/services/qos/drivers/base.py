# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
# Copyright 2016 Red Hat Inc.
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.api import validators as lib_validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from oslo_log import log as logging

from neutron.services.qos import qos_consts

LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class DriverBase(object):

    def __init__(self, name, vif_types, vnic_types,
                 supported_rules,
                 requires_rpc_notifications=False):
        """Instantiate a qos driver.

        :param name: driver name.
        :param vif_types: list of interfaces (VIFs) supported.
        :param vnic_types: list of vnic types supported.
        :param supported_rules: dict of supported rules.
        :param requires_rpc_notifications: indicates if this driver
               expects rpc push notifications to be sent from the driver.
        """

        self.name = name
        self.vif_types = vif_types
        self.vnic_types = vnic_types
        self.supported_rules = supported_rules
        self.requires_rpc_notifications = requires_rpc_notifications

    @registry.receives(qos_consts.QOS_PLUGIN, [events.AFTER_INIT])
    def _register(self, resource, event, trigger, **kwargs):
        if self.is_loaded:
            # trigger is the QosServiceDriverManager
            trigger.register_driver(self)

    def is_loaded(self):
        """True if the driver is active for the Neutron Server.

        Implement this property to determine if your driver is actively
        configured for this Neutron Server deployment.
        """
        return True

    def is_vif_type_compatible(self, vif_type):
        """True if the driver is compatible with the VIF type."""
        return vif_type in self.vif_types

    def is_vnic_compatible(self, vnic_type):
        """True if the driver is compatible with the specific VNIC type."""
        return vnic_type in self.vnic_types

    def is_rule_supported(self, rule):
        supported_parameters = self.supported_rules.get(rule.rule_type)
        if not supported_parameters:
            LOG.debug("Rule type %(rule_type)s is not supported by "
                      "%(driver_name)s",
                      {'rule_type': rule.rule_type,
                       'driver_name': self.name})
            return False
        for parameter, validators in supported_parameters.items():
            parameter_value = rule.get(parameter)
            for validator_type, validator_data in validators.items():
                validator_function = lib_validators.get_validator(
                    validator_type)
                validate_result = validator_function(parameter_value,
                                                     validator_data)
                # NOTE(slaweq): validator functions returns None if data is
                # valid or string with reason why data is not valid
                if validate_result:
                    LOG.debug("Parameter %(parameter)s=%(value)s in "
                              "rule type %(rule_type)s is not "
                              "supported by %(driver_name)s. "
                              "Validate result: %(validate_result)s",
                              {'parameter': parameter,
                               'value': parameter_value,
                               'rule_type': rule.rule_type,
                               'driver_name': self.name,
                               'validate_result': validate_result})
                    return False
        return True

    def create_policy(self, context, policy):
        """Create policy invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary with the specific policy
        information.

        :param context: current running context information
        :param policy: a QoSPolicy object being created, which will have no
                      rules.
        """

    def create_policy_precommit(self, context, policy):
        """Create policy precommit.

        This method can be implemented by the specific driver subclass
        to handle the precommit event of a policy that is being created.

        :param context: current running context information
        :param policy: a QoSPolicy object being created, which will have no
                      rules.
        """

    def update_policy(self, context, policy):
        """Update policy invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary.

        :param context: current running context information
        :param policy: a QoSPolicy object being updated.
        """

    def update_policy_precommit(self, context, policy):
        """Update policy precommit.

        This method can be implemented by the specific driver subclass
        to handle update precommit event of a policy that is being updated.

        :param context: current running context information
        :param policy: a QoSPolicy object being updated.
        """

    def delete_policy(self, context, policy):
        """Delete policy invocation.

        This method can be implemented by the specific driver subclass
        to delete the backend policy where necessary.

        :param context: current running context information
        :param policy: a QoSPolicy object being deleted
        """

    def delete_policy_precommit(self, context, policy):
        """Delete policy precommit.

        This method can be implemented by the specific driver subclass
        to handle delete precommit event of a policy that is being deleted.

        :param context: current running context information
        :param policy: a QoSPolicy object being deleted
        """
