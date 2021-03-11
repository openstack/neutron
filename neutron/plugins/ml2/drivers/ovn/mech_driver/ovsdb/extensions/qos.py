# Copyright 2020 Red Hat, Inc.
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

from ovsdbapp.backend.ovs_idl import idlutils

from neutron.objects.qos import binding as qos_binding
from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils


LOG = logging.getLogger(__name__)
OVN_QOS_DEFAULT_RULE_PRIORITY = 2002


class OVNClientQosExtension(object):
    """OVN client QoS extension"""

    def __init__(self, driver):
        LOG.info('Starting OVNClientQosExtension')
        super(OVNClientQosExtension, self).__init__()
        self._driver = driver
        self._plugin_property = None

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    @staticmethod
    def _qos_rules(context, policy_id):
        """QoS Neutron rules classified per direction and type

        :param context: (context) Neutron request context
        :param policy_id: (string) Neutron QoS policy ID
        :return: (dict) nested dictionary of QoS rules, classified per
                 direction and rule type
                 {egress: {bw_limit: {max_kbps, max_burst_kbps},
                           dscp: {dscp_mark}
                  ingress: {...} }
        """
        qos_rules = {constants.EGRESS_DIRECTION: {},
                     constants.INGRESS_DIRECTION: {}}
        if policy_id is None:
            return qos_rules

        # The policy might not have any rule
        all_rules = qos_rule.get_rules(qos_policy.QosPolicy,
                                       context, policy_id)
        for rule in all_rules:
            if isinstance(rule, qos_rule.QosBandwidthLimitRule):
                r = {rule.rule_type: {'max_kbps': rule.max_kbps}}
                if rule.max_burst_kbps:
                    r[rule.rule_type]['max_burst_kbps'] = rule.max_burst_kbps
                qos_rules[rule.direction].update(r)
            elif isinstance(rule, qos_rule.QosDscpMarkingRule):
                r = {rule.rule_type: {'dscp_mark': rule.dscp_mark}}
                qos_rules[constants.EGRESS_DIRECTION].update(r)
            else:
                LOG.warning('Rule type %(rule_type)s from QoS policy '
                            '%(policy_id)s is not supported in OVN',
                            {'rule_type': rule.rule_type,
                             'policy_id': policy_id})
        return qos_rules

    def _ovn_qos_rule(self, rules_direction, rules, port_id, network_id,
                      delete=False):
        """Generate an OVN QoS register based on several Neutron QoS rules

        A OVN QoS register can contain "bandwidth" and "action" parameters.
        "bandwidth" defines the rate speed limitation; "action" contains the
        DSCP value to apply. Both are not exclusive.
        Only one rule per port and direction can be applied; that's why
        two rules (bandwidth limit and DSCP) in the same direction must be
        combined in one OVN QoS register.
        http://www.openvswitch.org/support/dist-docs/ovn-nb.5.html

        :param rules_direction: (string) rules direction (egress, ingress).
        :param rules: (dict) {bw_limit: {max_kbps, max_burst_kbps},
                              dscp: {dscp_mark}}
        :param port_id: (string) port ID.
        :param network_id: (string) network ID.
        :param delete: (bool) defines if this rule if going to be a partial
                       one (without any bandwidth or DSCP information) to be
                       used only as deletion rule.
        :return: (dict) OVN QoS rule register to be used with QoSAddCommand
                 and QoSDelCommand.
        """
        if not delete and not rules:
            return

        lswitch_name = utils.ovn_name(network_id)

        if rules_direction == constants.EGRESS_DIRECTION:
            direction = 'from-lport'
            match = 'inport == "{}"'.format(port_id)
        else:
            direction = 'to-lport'
            match = 'outport == "{}"'.format(port_id)

        ovn_qos_rule = {'switch': lswitch_name, 'direction': direction,
                        'priority': OVN_QOS_DEFAULT_RULE_PRIORITY,
                        'match': match}

        if delete:
            # Any specific rule parameter is left undefined.
            return ovn_qos_rule

        for rule_type, rule in rules.items():
            if rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                ovn_qos_rule['rate'] = rule['max_kbps']
                if rule.get('max_burst_kbps'):
                    ovn_qos_rule['burst'] = rule['max_burst_kbps']
            elif rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
                ovn_qos_rule.update({'dscp': rule['dscp_mark']})

        return ovn_qos_rule

    def _port_effective_qos_policy_id(self, port):
        """Return port effective QoS policy

        If the port does not have any QoS policy reference or is a network
        device, then return None.
        """
        policy_exists = bool(port.get('qos_policy_id') or
                             port.get('qos_network_policy_id'))
        if not policy_exists or utils.is_network_device_port(port):
            return None, None

        if port.get('qos_policy_id'):
            return port['qos_policy_id'], 'port'
        else:
            return port['qos_network_policy_id'], 'network'

    def _update_port_qos_rules(self, txn, port_id, network_id, qos_policy_id,
                               qos_rules):
        # NOTE(ralonsoh): we don't use the transaction context because the
        # QoS policy could belong to another user (network QoS policy).
        admin_context = n_context.get_admin_context()

        # Generate generic deletion rules for both directions. In case of
        # creating deletion rules, the rule content is irrelevant.
        for ovn_rule in [self._ovn_qos_rule(direction, {}, port_id,
                                            network_id, delete=True)
                         for direction in constants.VALID_DIRECTIONS]:
            # TODO(lucasagomes): qos_del() in ovsdbapp doesn't support
            # if_exists=True
            try:
                txn.add(self._driver._nb_idl.qos_del(**ovn_rule))
            except idlutils.RowNotFound:
                continue

        if not qos_policy_id:
            return  # If no QoS policy is defined, there are no QoS rules.

        # TODO(ralonsoh): for update_network and update_policy operations,
        # the QoS rules can be retrieved only once.
        qos_rules = qos_rules or self._qos_rules(admin_context, qos_policy_id)
        for direction, rules in qos_rules.items():
            ovn_rule = self._ovn_qos_rule(direction, rules, port_id,
                                          network_id)
            if ovn_rule:
                txn.add(self._driver._nb_idl.qos_add(**ovn_rule))

    def create_port(self, txn, port, port_type=None):
        self.update_port(txn, port, None, reset=True, port_type=port_type)

    def delete_port(self, txn, port):
        self.update_port(txn, port, None, delete=True)

    def update_port(self, txn, port, original_port, reset=False, delete=False,
                    qos_rules=None, port_type=None):
        if port_type == ovn_const.LSP_TYPE_EXTERNAL:
            # External ports (SR-IOV) QoS is handled the SR-IOV agent QoS
            # extension.
            return

        if (not reset and not original_port) and not delete:
            # If there is no information about the previous QoS policy, do not
            # make any change, unless the port is new or the QoS information
            # must be reset (delete any previous configuration and set new
            # one).
            return

        qos_policy_id = (None if delete else
                         self._port_effective_qos_policy_id(port)[0])
        if not reset and not delete:
            original_qos_policy_id = self._port_effective_qos_policy_id(
                original_port)[0]
            if qos_policy_id == original_qos_policy_id:
                return  # No QoS policy change

        self._update_port_qos_rules(txn, port['id'], port['network_id'],
                                    qos_policy_id, qos_rules)

    def update_network(self, txn, network, original_network, reset=False,
                       qos_rules=None):
        updated_port_ids = set([])
        if not reset and not original_network:
            # If there is no information about the previous QoS policy, do not
            # make any change.
            return updated_port_ids

        qos_policy_id = network.get('qos_policy_id')
        if not reset:
            original_qos_policy_id = original_network.get('qos_policy_id')
            if qos_policy_id == original_qos_policy_id:
                return updated_port_ids  # No QoS policy change

        # NOTE(ralonsoh): we don't use the transaction context because some
        # ports can belong to other projects.
        admin_context = n_context.get_admin_context()
        for port in qos_binding.QosPolicyPortBinding.get_ports_by_network_id(
                admin_context, network['id']):
            if utils.is_network_device_port(port):
                continue

            self._update_port_qos_rules(txn, port['id'], network['id'],
                                        qos_policy_id, qos_rules)
            updated_port_ids.add(port['id'])

        return updated_port_ids

    def update_policy(self, context, policy):
        updated_port_ids = set([])
        bound_networks = policy.get_bound_networks()
        bound_ports = policy.get_bound_ports()
        qos_rules = self._qos_rules(context, policy.id)
        # TODO(ralonsoh): we need to benchmark this transaction in systems with
        # a huge amount of ports. This can take a while and could block other
        # operations.
        with self._driver._nb_idl.transaction(check_error=True) as txn:
            for network_id in bound_networks:
                network = {'qos_policy_id': policy.id, 'id': network_id}
                updated_port_ids.update(
                    self.update_network(txn, network, {}, reset=True,
                                        qos_rules=qos_rules))

            # Update each port bound to this policy, not handled previously in
            # the network update loop
            port_ids = [p for p in bound_ports if p not in updated_port_ids]
            for port in self._plugin.get_ports(context,
                                               filters={'id': port_ids}):
                self.update_port(txn, port, {}, reset=True,
                                 qos_rules=qos_rules)
