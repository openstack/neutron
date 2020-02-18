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

from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib.db import constants as db_consts
from neutron_lib.plugins import directory
from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_log import log as logging

from neutron.common.ovn import utils

LOG = logging.getLogger(__name__)

OVN_QOS = 'qos'
SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': constants.VALID_DIRECTIONS},
    },
    qos_consts.RULE_TYPE_DSCP_MARKING: {
        qos_consts.DSCP_MARK: {'type:values': constants.VALID_DSCP_MARKS},
    }
}

VIF_TYPES = [portbindings.VIF_TYPE_OVS, portbindings.VIF_TYPE_VHOST_USER]
VNIC_TYPES = [portbindings.VNIC_NORMAL]


class OVNQosNotificationDriver(base.DriverBase):
    """OVN notification driver for QoS."""

    def __init__(self, name='OVNQosDriver',
                 vif_types=VIF_TYPES,
                 vnic_types=VNIC_TYPES,
                 supported_rules=SUPPORTED_RULES,
                 requires_rpc_notifications=False):
        super(OVNQosNotificationDriver, self).__init__(
            name, vif_types, vnic_types, supported_rules,
            requires_rpc_notifications)

    @classmethod
    def create(cls, plugin_driver):
        cls._driver = plugin_driver
        return cls()

    @property
    def is_loaded(self):
        return OVN_QOS in cfg.CONF.ml2.extension_drivers

    def create_policy(self, context, policy):
        # No need to update OVN on create
        pass

    def update_policy(self, context, policy):
        # Call into OVN client to update the policy
        self._driver._ovn_client._qos_driver.update_policy(context, policy)

    def delete_policy(self, context, policy):
        # No need to update OVN on delete
        pass


class OVNQosDriver(object):
    """Qos driver for OVN"""

    def __init__(self, driver):
        LOG.info("Starting OVNQosDriver")
        super(OVNQosDriver, self).__init__()
        self._driver = driver
        self._plugin_property = None

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _generate_port_options(self, context, policy_id):
        if policy_id is None:
            return {}
        options = {}
        # The policy might not have any rules
        all_rules = qos_rule.get_rules(qos_policy.QosPolicy,
                                       context, policy_id)
        for rule in all_rules:
            if isinstance(rule, qos_rule.QosBandwidthLimitRule):
                options['qos_max_rate'] = rule.max_kbps
                if rule.max_burst_kbps:
                    options['qos_burst'] = rule.max_burst_kbps
                options['direction'] = rule.direction
            if isinstance(rule, qos_rule.QosDscpMarkingRule):
                options['dscp_mark'] = rule.dscp_mark
                options['direction'] = constants.EGRESS_DIRECTION
        return options

    def get_qos_options(self, port):
        # Is qos service enabled
        if 'qos_policy_id' not in port:
            return {}
        # Don't apply qos rules to network devices
        if utils.is_network_device_port(port):
            return {}

        # Determine if port or network policy should be used
        context = n_context.get_admin_context()
        port_policy_id = port.get('qos_policy_id')
        network_policy_id = None
        if not port_policy_id:
            network_policy = qos_policy.QosPolicy.get_network_policy(
                context, port['network_id'])
            network_policy_id = network_policy.id if network_policy else None

        # Generate qos options for the selected policy
        policy_id = port_policy_id or network_policy_id
        return self._generate_port_options(context, policy_id)

    def _update_network_ports(self, context, network_id, options):
        # Retrieve all ports for this network
        ports = self._plugin.get_ports(context,
                                       filters={'network_id': [network_id]})
        for port in ports:
            # Don't apply qos rules if port has a policy
            port_policy_id = port.get('qos_policy_id')
            if port_policy_id:
                continue
            # Don't apply qos rules to network devices
            if utils.is_network_device_port(port):
                continue
            # Call into OVN client to update port
            self._driver.update_port(port, qos_options=options)

    def update_network(self, network):
        # Is qos service enabled
        if 'qos_policy_id' not in network:
            return

        # Update the qos options on each network port
        context = n_context.get_admin_context()
        options = self._generate_port_options(
            context, network['qos_policy_id'])
        self._update_network_ports(context, network.get('id'), options)

    def update_policy(self, context, policy):
        options = self._generate_port_options(context, policy.id)

        # Update each network bound to this policy
        network_bindings = policy.get_bound_networks()
        for network_id in network_bindings:
            self._update_network_ports(context, network_id, options)

        # Update each port bound to this policy
        port_bindings = policy.get_bound_ports()
        for port_id in port_bindings:
            port = self._plugin.get_port(context, port_id)
            self._driver.update_port(port, qos_options=options)
