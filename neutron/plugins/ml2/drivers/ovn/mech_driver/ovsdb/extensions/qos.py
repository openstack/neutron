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
import copy

from neutron.objects.qos import binding as qos_binding
from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron_lib.api.definitions import l3 as l3_api
from neutron_lib.api.definitions import provider_net as pnet_api
from neutron_lib import constants
from neutron_lib.plugins import constants as plugins_const
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf


LOG = logging.getLogger(__name__)
OVN_QOS_DEFAULT_RULE_PRIORITY = 2002
OVN_QOS_FIP_RULE_PRIORITY = 2003
_MIN_RATE = ovn_const.LSP_OPTIONS_QOS_MIN_RATE
# NOTE(ralonsoh): this constant will be in neutron_lib.constants
TYPE_PHYSICAL = (constants.TYPE_FLAT, constants.TYPE_VLAN)


class OVNClientQosExtension:
    """OVN client QoS extension"""

    def __init__(self, driver=None, nb_idl=None):
        LOG.info('Starting OVNClientQosExtension')
        super().__init__()
        self._driver = driver
        self._nb_idl = nb_idl
        self._plugin_property = None
        self._plugin_l3_property = None

    @property
    def nb_idl(self):
        if not self._nb_idl:
            self._nb_idl = self._driver._nb_idl
        return self._nb_idl

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    @property
    def _plugin_l3(self):
        if self._plugin_l3_property is None:
            self._plugin_l3_property = directory.get_plugin(plugins_const.L3)
        return self._plugin_l3_property

    @staticmethod
    def _qos_rules(context, policy_id):
        """QoS Neutron rules classified per direction and type

        :param context: (context) Neutron request context
        :param policy_id: (string) Neutron QoS policy ID
        :return: (dict) nested dictionary of QoS rules, classified per
                 direction and rule type
                 {egress: {bw_limit: {max_kbps, max_burst_kbps},
                           dscp: {dscp_mark},
                           min_kbps: {min_kbps},
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
            elif isinstance(rule, qos_rule.QosMinimumBandwidthRule):
                if rule.direction == constants.INGRESS_DIRECTION:
                    LOG.warning('ML2/OVN QoS driver does not support minimum '
                                'bandwidth rules enforcement with ingress '
                                'direction')
                else:
                    r = {rule.rule_type: {'min_kbps': rule.min_kbps}}
                    qos_rules[constants.EGRESS_DIRECTION].update(r)
            else:
                LOG.warning('Rule type %(rule_type)s from QoS policy '
                            '%(policy_id)s is not supported in OVN',
                            {'rule_type': rule.rule_type,
                             'policy_id': policy_id})
        return qos_rules

    @staticmethod
    def _ovn_qos_rule_match(direction, port_id, ip_address, resident_port):
        if direction == constants.EGRESS_DIRECTION:
            in_or_out = 'inport'
            src_or_dst = 'src'
        else:
            in_or_out = 'outport'
            src_or_dst = 'dst'

        match = f'{in_or_out} == "{port_id}"'
        if ip_address and resident_port:
            match += (' && ip4.%s == %s && is_chassis_resident("%s")' %
                      (src_or_dst, ip_address, resident_port))

        return match

    def _ovn_qos_rule(self, rules_direction, rules, port_id, network_id,
                      fip_id=None, ip_address=None, resident_port=None,
                      router_id=None):
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
                              dscp: {dscp_mark},
                              minimum_bandwidth: {min_kbps}}
        :param port_id: (string) port ID; for L3 floating IP bandwidth
                        limit this is the router gateway port ID.
        :param network_id: (string) network ID.
        :param fip_id: (string) floating IP ID, for L3 floating IP bandwidth
                       limit.
        :param ip_address: (string) IP address, for L3 floating IP bandwidth
                           limit.
        :param resident_port: (string) for L3 floating IP bandwidth, this is
                              a logical switch port located in the chassis
                              where the floating IP traffic is NATed.
        :param router_id: (string) router ID, for L3 router gateway port
                          bandwidth limit.
        :return: (dict) OVN QoS rule register to be used with QoSAddCommand
                 and QoSDelCommand.
        """
        lswitch_name = utils.ovn_name(network_id)
        direction = (
            'from-lport' if rules_direction == constants.EGRESS_DIRECTION else
            'to-lport')
        match = self._ovn_qos_rule_match(rules_direction, port_id, ip_address,
                                         resident_port)

        priority = (OVN_QOS_FIP_RULE_PRIORITY if fip_id else
                    OVN_QOS_DEFAULT_RULE_PRIORITY)
        ovn_qos_rule = {'switch': lswitch_name,
                        'direction': direction,
                        'priority': priority,
                        'match': match}

        if not rules:
            # Any specific rule parameter is left undefined.
            return ovn_qos_rule

        for rule_type, rule in rules.items():
            if rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                ovn_qos_rule['rate'] = rule['max_kbps']
                if rule.get('max_burst_kbps'):
                    ovn_qos_rule['burst'] = rule['max_burst_kbps']
            elif rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
                ovn_qos_rule['dscp'] = rule['dscp_mark']
            # NOTE(ralonsoh): OVN QoS registers don't have minimum rate rules.

        if (ovn_qos_rule.get('rate') is None and
                ovn_qos_rule.get('dscp') is None):
            # Any specific rule parameter is left undefined, no OVN QoS rules
            # defined.
            return ovn_qos_rule

        # All OVN QoS rules have an external ID reference to the port or the
        # FIP that are attached to.
        # 1) L3 floating IP ports.
        if fip_id:
            key, value = ovn_const.OVN_FIP_EXT_ID_KEY, fip_id
        # 2) L3 router gateway port.
        elif router_id:
            key, value = ovn_const.OVN_ROUTER_ID_EXT_ID_KEY, router_id
        # 3) Fixed IP ports (aka VM ports)
        else:
            key, value = ovn_const.OVN_PORT_EXT_ID_KEY, port_id
        ovn_qos_rule['external_ids'] = {key: value}

        return ovn_qos_rule

    def get_lsp_options_qos(self, port_id):
        """Return the current LSP.options QoS fields, passing the port ID"""
        qos_options = {}
        lsp = self.nb_idl.lookup('Logical_Switch_Port', port_id, default=None)
        if not lsp:
            return {}

        for qos_key in (ovn_const.LSP_OPTIONS_QOS_MAX_RATE,
                        ovn_const.LSP_OPTIONS_QOS_BURST,
                        ovn_const.LSP_OPTIONS_QOS_MIN_RATE):
            qos_value = lsp.options.get(qos_key)
            if qos_value is not None:
                qos_options[qos_key] = qos_value
        return qos_options

    @staticmethod
    def _ovn_lsp_rule(rules):
        """Generate the OVN LSP.options for physical network ports (egress)

        The Logical_Switch_Port options field is a dictionary that can contain
        the following options:
        * qos_min_rate: (str) indicates the minimum guaranteed rate available
          for data sent from this interface, in bit/s.
        * qos_max_rate: (str) indicates the maximum rate for data sent from
          this interface, in bit/s.
        * qos_burst: (str) indicates the maximum burst size for data sent from
          this interface, in bits.
        (from https://www.ovn.org/support/dist-docs/ovn-nb.5.html)

        :param rules: (dict) {bw_limit: {max_kbps, max_burst_kbps},
                              dscp: {dscp_mark},
                              minimum_bandwidth: {min_kbps}}
                             An empty dictionary will create a deletion rule.
        :param port_id: (string) port ID; for L3 floating IP bandwidth
                        limit this is the router gateway port ID.
        :return: (dict) a dictionary with the QoS rules to be updated with the
                 LSP.options field. By default, the values of the QoS
                 parameters are None. In that case, the keys are removed from
                 the LSP.options dictionary (check
                 ``UpdateLSwitchPortQosOptionsCommand``).
        """
        ovn_lsp_rule = {ovn_const.LSP_OPTIONS_QOS_MAX_RATE: None,
                        ovn_const.LSP_OPTIONS_QOS_BURST: None,
                        ovn_const.LSP_OPTIONS_QOS_MIN_RATE: None}
        # NOTE(ralonsoh): the rate values must be defined in bits/s and bits.
        # It is used the SI_BASE=1000 constant to convert from kbits/s and
        # kbits.
        for rule_type, rule in rules.items():
            if rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                qos_max_rate = str(rule['max_kbps'] * constants.SI_BASE)
                ovn_lsp_rule[ovn_const.LSP_OPTIONS_QOS_MAX_RATE] = qos_max_rate
                if rule.get('max_burst_kbps'):
                    qos_burst = str(rule['max_burst_kbps'] * constants.SI_BASE)
                    ovn_lsp_rule[ovn_const.LSP_OPTIONS_QOS_BURST] = qos_burst
            elif rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
                qos_min_rate = str(rule['min_kbps'] * constants.SI_BASE)
                ovn_lsp_rule[ovn_const.LSP_OPTIONS_QOS_MIN_RATE] = qos_min_rate
        return ovn_lsp_rule

    def _apply_ovn_rule_qos(self, txn, rules, ovn_rule_qos):
        """Add or remove the OVN QoS rules (for max-bw and DSCP rules only).

        :param txn: the ovsdbapp transaction object.
        :param rules: Neutron QoS rules (per direction).
        :param ovn_rule_qos: dictionary with the Neutron QoS rules with the
                             parameters needed to call ``qos_add`` or
                             ``qos_del`` commands.
        """
        if rules and not (ovn_rule_qos.get('rate') is None and
                          ovn_rule_qos.get('dscp') is None):
            # NOTE(ralonsoh): with "may_exist=True", the "qos_add" will
            # create the QoS OVN rule or update the existing one.
            # NOTE(ralonsoh): if the Neutron QoS rules don't have at least
            # a max-bw rule or a DSCP rule, skip this command.
            txn.add(self.nb_idl.qos_add(**ovn_rule_qos, may_exist=True))
        else:
            # Delete, if exists, the QoS rule in this direction.
            txn.add(self.nb_idl.qos_del(**ovn_rule_qos, if_exists=True))

    def _update_lsp_qos_options(self, txn, lsp, port_id, ovn_rule_lsp):
        """Update the LSP QoS options

        :param txn: the ovsdbapp transaction object.
        :param lsp: (AddLSwitchPortCommand) logical switch port command, passed
                    when the port is being created. Because this method is
                    called inside the OVN DB transaction, the LSP has not been
                    created yet nor update in the IDL local cache.
        :param port_id: (str) Neutron port ID that matches the LSP.name.
                        If the port ID is None, the OVN QoS rule does not
                        apply to a LSP but to a router gateway port or a
                        floating IP.
        :param ovn_rule_lsp: (dict) dictionary with the QoS values to be set in
                             the LSP.options. If the values are None, the keys
                             are removed.
        """
        lsp = lsp or port_id
        if lsp:
            txn.add(self.nb_idl.update_lswitch_qos_options(lsp,
                                                           **ovn_rule_lsp))

    @staticmethod
    def port_effective_qos_policy_id(port):
        """Return port effective QoS policy

        If the port does not have any QoS policy reference or is a network
        device, then return None.
        """
        policy_id = n_utils.effective_qos_policy_id(port)
        if not policy_id or utils.is_network_device_port(port):
            return None, None

        if port.get('qos_policy_id'):
            return port['qos_policy_id'], 'port'
        return port['qos_network_policy_id'], 'network'

    def _delete_port_qos_rules(self, txn, port_id, network_id, network_type,
                               lsp=None):
        # Generate generic deletion rules for both directions. In case of
        # creating deletion rules, the rule content is irrelevant.
        for ovn_rule_qos in (self._ovn_qos_rule(direction, {}, port_id,
                                                network_id)
                             for direction in constants.VALID_DIRECTIONS):
            txn.add(self.nb_idl.qos_del(**ovn_rule_qos))

        if network_type in TYPE_PHYSICAL:
            self._update_lsp_qos_options(txn, lsp, port_id,
                                         self._ovn_lsp_rule({}))

    def _add_port_qos_rules(self, context, txn, port_id, network_id,
                            network_type, qos_policy_id, qos_rules, lsp=None):
        # NOTE(ralonsoh): the QoS policy could belong to another user (network
        # QoS policy), admin permissions are needed.
        admin_context = context.elevated()

        # TODO(ralonsoh): for update_network and update_policy operations,
        # the QoS rules can be retrieved only once.
        _qos_rules = (copy.deepcopy(qos_rules) if qos_rules else
                      self._qos_rules(admin_context, qos_policy_id))
        for direction, rules in _qos_rules.items():
            min_bw = rules.get(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH)
            # NOTE(ralonsoh): the QoS rules are defined in the LSP.options
            # dictionary if (1) direction=egress, (2) the network is physical
            # and (3) there are min-bw rules. Otherwise, the OVN QoS registers
            # are used (OVN BW policer).
            if (network_type in TYPE_PHYSICAL and
                    direction == constants.EGRESS_DIRECTION):
                if min_bw:
                    ovn_rule_lsp = self._ovn_lsp_rule(rules)
                    self._update_lsp_qos_options(txn, lsp, port_id,
                                                 ovn_rule_lsp)
                    # In this particular case, the QoS rules should be defined
                    # in LSP.options. Only DSCP rule will create a QoS entry.
                    rules.pop(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT, None)
                    rules.pop(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH, None)
                else:
                    # Clear the LSP.options QoS rules.
                    self._update_lsp_qos_options(txn, lsp, port_id,
                                                 self._ovn_lsp_rule({}))

            ovn_rule_qos = self._ovn_qos_rule(direction, rules, port_id,
                                              network_id)
            self._apply_ovn_rule_qos(txn, rules, ovn_rule_qos)

    def _update_port_qos_rules(self, context, txn, port_id, network_id,
                               network_type, qos_policy_id, qos_rules,
                               lsp=None):
        if not qos_policy_id:
            self._delete_port_qos_rules(txn, port_id, network_id, network_type,
                                        lsp=lsp)
        else:
            self._add_port_qos_rules(context, txn, port_id, network_id,
                                     network_type, qos_policy_id, qos_rules,
                                     lsp=lsp)

    def create_port(self, context, txn, port, lsp):
        self.update_port(context, txn, port, None, reset=True, lsp=lsp)

    def delete_port(self, context, txn, port):
        self.update_port(context, txn, port, None, delete=True)

    def update_port(self, context, txn, port, original_port, reset=False,
                    delete=False, qos_rules=None, lsp=None):
        if utils.is_port_external(port):
            # External ports (SR-IOV) QoS is handled by the SR-IOV agent QoS
            # extension.
            return

        if (not reset and not original_port) and not delete:
            # If there is no information about the previous QoS policy, do not
            # make any change, unless the port is new or the QoS information
            # must be reset (delete any previous configuration and set new
            # one).
            return

        qos_policy_id = (None if delete else
                         self.port_effective_qos_policy_id(port)[0])
        if not reset and not delete:
            original_qos_policy_id = self.port_effective_qos_policy_id(
                original_port)[0]
            if qos_policy_id == original_qos_policy_id:
                return  # No QoS policy change

        net_name = utils.ovn_name(port['network_id'])
        ls = self.nb_idl.ls_get(net_name).execute(check_errors=True)
        network_type = ls.external_ids[ovn_const.OVN_NETTYPE_EXT_ID_KEY]
        self._update_port_qos_rules(
            context, txn, port['id'], port['network_id'], network_type,
            qos_policy_id, qos_rules, lsp=lsp)

    def update_network(self, context, txn, network, original_network,
                       reset=False, qos_rules=None):
        updated_port_ids = set()
        updated_fip_ids = set()
        updated_router_ids = set()
        if not reset and not original_network:
            # If there is no information about the previous QoS policy, do not
            # make any change.
            return updated_port_ids, updated_fip_ids, updated_router_ids

        qos_policy_id = network.get('qos_policy_id')
        if not reset:
            original_qos_policy_id = original_network.get('qos_policy_id')
            if qos_policy_id == original_qos_policy_id:
                # No QoS policy change
                return updated_port_ids, updated_fip_ids, updated_router_ids

        # NOTE(ralonsoh): some ports can belong to other projects,
        # admin permissions are needed.
        admin_context = context.elevated()
        for port in qos_binding.QosPolicyPortBinding.get_ports_by_network_id(
                admin_context, network['id']):
            if (utils.is_network_device_port(port) or
                    utils.is_port_external(port)):
                continue
            network_type = network[pnet_api.NETWORK_TYPE]
            self._update_port_qos_rules(
                context, txn, port['id'], network['id'], network_type,
                qos_policy_id, qos_rules)
            updated_port_ids.add(port['id'])

        fips = qos_binding.QosPolicyFloatingIPBinding.get_fips_by_network_id(
            admin_context, network['id'])
        fip_ids = [fip.id for fip in fips]
        for floatingip in self._plugin_l3.get_floatingips(
                admin_context, filters={'id': fip_ids}):
            self.update_floatingip(admin_context, txn, floatingip)
            updated_fip_ids.add(floatingip['id'])

        for router in (qos_binding.QosPolicyRouterGatewayIPBinding.
                       get_routers_by_network_id(admin_context,
                                                 network['id'])):
            router_dict = self._plugin_l3._make_router_dict(router)
            self.update_router(admin_context, txn, router_dict)
            updated_router_ids.add(router.id)

        return updated_port_ids, updated_fip_ids, updated_router_ids

    def _delete_fip_qos_rules(self, txn, fip_id, network_id):
        if network_id:
            lswitch_name = utils.ovn_name(network_id)
            txn.add(self.nb_idl.qos_del_ext_ids(
                lswitch_name,
                {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}))

    def create_floatingip(self, context, txn, floatingip):
        self.update_floatingip(context, txn, floatingip)

    def update_floatingip(self, context, txn, floatingip):
        router_id = floatingip.get('router_id')
        qos_policy_id = (floatingip.get('qos_policy_id') or
                         floatingip.get('qos_network_policy_id'))

        if not (router_id and qos_policy_id):
            return self._delete_fip_qos_rules(
                txn, floatingip['id'], floatingip['floating_network_id'])

        admin_context = context.elevated()
        router_db = self._plugin_l3._get_router(admin_context, router_id)
        gw_port_id = router_db.get('gw_port_id')
        if not gw_port_id:
            return self._delete_fip_qos_rules(
                txn, floatingip['id'], floatingip['floating_network_id'])

        if ovn_conf.is_ovn_distributed_floating_ip():
            # DVR, floating IP GW is in the same compute node as private port.
            resident_port = floatingip['port_id']
        else:
            # Non-DVR, floating IP GW is located where chassisredirect lrp is.
            resident_port = utils.ovn_cr_lrouter_port_name(gw_port_id)

        qos_rules = self._qos_rules(admin_context, qos_policy_id)
        for direction, rules in qos_rules.items():
            ovn_rule_qos = self._ovn_qos_rule(
                direction, rules, gw_port_id,
                floatingip['floating_network_id'], fip_id=floatingip['id'],
                ip_address=floatingip['floating_ip_address'],
                resident_port=resident_port)
            self._apply_ovn_rule_qos(txn, rules, ovn_rule_qos)

    def delete_floatingip(self, context, txn, floatingip):
        self.update_floatingip(context, txn, floatingip)

    def disassociate_floatingip(self, context, txn, floatingip):
        self.delete_floatingip(context, txn, floatingip)

    def create_router(self, context, txn, router):
        self.update_router(context, txn, router)

    def update_router(self, context, txn, router):
        gw_info = router.get(l3_api.EXTERNAL_GW_INFO) or {}
        qos_policy_id = n_utils.effective_qos_policy_id(router)
        router_id = router.get('id')
        gw_port_id = router.get('gw_port_id')
        gw_network_id = gw_info.get('network_id')
        if not (router_id and gw_port_id and gw_network_id):
            # NOTE(ralonsoh): when the gateway network is detached, the gateway
            # port is deleted. Any QoS policy related to this port_id is
            # deleted in "self.update_port()".
            LOG.debug('Router %s does not have ID or gateway assigned',
                      router_id)
            return

        admin_context = context.elevated()
        qos_rules = self._qos_rules(admin_context, qos_policy_id)
        for direction, rules in qos_rules.items():
            ovn_rule_qos = self._ovn_qos_rule(
                direction, rules, gw_port_id, gw_network_id,
                router_id=router_id)
            self._apply_ovn_rule_qos(txn, rules, ovn_rule_qos)

    def update_policy(self, context, policy):
        updated_port_ids = set()
        updated_fip_ids = set()
        updated_router_ids = set()
        bound_networks = policy.get_bound_networks()
        bound_ports = policy.get_bound_ports()
        bound_fips = policy.get_bound_floatingips()
        bound_routers = policy.get_bound_routers()
        qos_rules = self._qos_rules(context, policy.id)
        # TODO(ralonsoh): we need to benchmark this transaction in systems with
        # a huge amount of ports. This can take a while and could block other
        # operations.
        with self.nb_idl.transaction(check_error=True) as txn:
            for network_id in bound_networks:
                ls = self._nb_idl.ls_get(utils.ovn_name(network_id)).execute(
                    check_errors=True)
                net_type = ls.external_ids[ovn_const.OVN_NETTYPE_EXT_ID_KEY]
                network = {'qos_policy_id': policy.id,
                           'id': network_id,
                           pnet_api.NETWORK_TYPE: net_type,
                           }
                port_ids, fip_ids, router_ids = self.update_network(
                    context, txn, network, {}, reset=True, qos_rules=qos_rules)
                updated_port_ids.update(port_ids)
                updated_fip_ids.update(fip_ids)
                updated_router_ids.update(router_ids)

            # Update each port bound to this policy, not handled previously in
            # the network update loop
            port_ids = [p for p in bound_ports if p not in updated_port_ids]
            if port_ids:
                for port in self._plugin.get_ports(context,
                                                   filters={'id': port_ids}):
                    self.update_port(context, txn, port, {}, reset=True,
                                     qos_rules=qos_rules)

            # Update each FIP bound to this policy, not handled previously in
            # the network update loop
            fip_ids = [fip for fip in bound_fips if fip not in updated_fip_ids]
            if fip_ids:
                for fip in self._plugin_l3.get_floatingips(
                        context, filters={'id': fip_ids}):
                    self.update_floatingip(context, txn, fip)

            router_ids = [r for r in bound_routers if
                          r not in updated_router_ids]
            if router_ids:
                for router in self._plugin_l3.get_routers(
                        context, filters={'id': router_ids}):
                    self.update_router(context, txn, router)
