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

from neutron.objects.qos import binding as qos_binding
from neutron.objects.qos import policy as qos_policy
from neutron.objects.qos import rule as qos_rule
from neutron_lib.api.definitions import l3 as l3_api
from neutron_lib import constants
from neutron_lib import context as n_context
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
_MIN_RATE = ovn_const.LSP_OPTIONS_QOS_MIN_RATE


class OVNClientQosExtension(object):
    """OVN client QoS extension"""

    def __init__(self, driver=None, nb_idl=None):
        LOG.info('Starting OVNClientQosExtension')
        super(OVNClientQosExtension, self).__init__()
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

        match = '%s == "%s"' % (in_or_out, port_id)
        if ip_address and resident_port:
            match += (' && ip4.%s == %s && is_chassis_resident("%s")' %
                      (src_or_dst, ip_address, resident_port))

        return match

    def _ovn_qos_rule(self, rules_direction, rules, port_id, network_id,
                      fip_id=None, ip_address=None, resident_port=None,
                      router_id=None, delete=False):
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
        :param delete: (bool) defines if this rule if going to be a partial
                       one (without any bandwidth or DSCP information) to be
                       used only as deletion rule.
        :return: (dict) OVN QoS rule register to be used with QoSAddCommand
                 and QoSDelCommand.
        """
        if not delete and not rules:
            return

        lswitch_name = utils.ovn_name(network_id)
        direction = (
            'from-lport' if rules_direction == constants.EGRESS_DIRECTION else
            'to-lport')
        match = self._ovn_qos_rule_match(rules_direction, port_id, ip_address,
                                         resident_port)

        ovn_qos_rule = {'switch': lswitch_name, 'direction': direction,
                        'priority': OVN_QOS_DEFAULT_RULE_PRIORITY,
                        'match': match}

        if delete:
            # Any specific rule parameter is left undefined.
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

        for rule_type, rule in rules.items():
            if rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                ovn_qos_rule['rate'] = rule['max_kbps']
                if rule.get('max_burst_kbps'):
                    ovn_qos_rule['burst'] = rule['max_burst_kbps']
            elif rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
                ovn_qos_rule.update({'dscp': rule['dscp_mark']})
            elif rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
                # NOTE(ralonsoh): minimum bandwidth rules are only supported
                # for fixed IP ports (although this check is redundant, that
                # ensures only fixed IP ports have this rule type in the
                # returned dictionary).
                if key == ovn_const.OVN_PORT_EXT_ID_KEY:
                    ovn_qos_rule[_MIN_RATE] = str(rule['min_kbps'])

        return ovn_qos_rule

    def _update_lsp_qos_options(self, txn, lsp, port_id, min_qos_value):
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
        :param min_qos_value: (str) minimum bandwidth rule value in kbps; it is
                              a string because LSP.options is a {str:str} dict.
        """
        lsp = lsp or self.nb_idl.lsp_get(port_id).execute()
        if not lsp:
            return

        options = {_MIN_RATE: min_qos_value}
        txn.add(self.nb_idl.update_lswitch_qos_options(lsp, **options))

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
        else:
            return port['qos_network_policy_id'], 'network'

    def _delete_port_qos_rules(self, txn, port_id, network_id, lsp=None,
                               port_deleted=False):
        # Generate generic deletion rules for both directions. In case of
        # creating deletion rules, the rule content is irrelevant.
        for ovn_rule in [self._ovn_qos_rule(direction, {}, port_id,
                                            network_id, delete=True)
                         for direction in constants.VALID_DIRECTIONS]:
            min_qos_value = ovn_rule.pop(_MIN_RATE, None)
            txn.add(self.nb_idl.qos_del(**ovn_rule))
            if not port_deleted:
                self._update_lsp_qos_options(txn, lsp, port_id,
                                             min_qos_value)

    def _add_port_qos_rules(self, txn, port_id, network_id, qos_policy_id,
                            qos_rules, lsp=None):
        # NOTE(ralonsoh): we don't use the transaction context because the
        # QoS policy could belong to another user (network QoS policy).
        admin_context = n_context.get_admin_context()

        # TODO(ralonsoh): for update_network and update_policy operations,
        # the QoS rules can be retrieved only once.
        qos_rules = qos_rules or self._qos_rules(admin_context, qos_policy_id)
        for direction, rules in qos_rules.items():
            # "delete=not rule": that means, when we don't have rules, we
            # generate a "ovn_rule" to be used as input in a "qos_del" method.
            ovn_rule = self._ovn_qos_rule(direction, rules, port_id,
                                          network_id, delete=not rules)
            min_qos_value = ovn_rule.pop(_MIN_RATE, None)
            if rules:
                # NOTE(ralonsoh): with "may_exist=True", the "qos_add" will
                # create the QoS OVN rule or update the existing one.
                txn.add(self.nb_idl.qos_add(**ovn_rule, may_exist=True))
            else:
                # Delete, if exists, the QoS rule in this direction.
                txn.add(self.nb_idl.qos_del(**ovn_rule, if_exists=True))
            self._update_lsp_qos_options(txn, lsp, port_id, min_qos_value)

    def _update_port_qos_rules(self, txn, port_id, network_id, qos_policy_id,
                               qos_rules, lsp=None, port_deleted=False):
        if not qos_policy_id:
            self._delete_port_qos_rules(txn, port_id, network_id, lsp=lsp,
                                        port_deleted=port_deleted)
        else:
            self._add_port_qos_rules(txn, port_id, network_id, qos_policy_id,
                                     qos_rules, lsp=lsp)

    def create_port(self, txn, port, lsp):
        self.update_port(txn, port, None, reset=True, lsp=lsp)

    def delete_port(self, txn, port):
        self.update_port(txn, port, None, delete=True)

    def update_port(self, txn, port, original_port, reset=False, delete=False,
                    qos_rules=None, lsp=None):
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

        self._update_port_qos_rules(txn, port['id'], port['network_id'],
                                    qos_policy_id, qos_rules, lsp=lsp,
                                    port_deleted=delete)

    def update_network(self, txn, network, original_network, reset=False,
                       qos_rules=None):
        updated_port_ids = set([])
        updated_fip_ids = set([])
        updated_router_ids = set([])
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

        # NOTE(ralonsoh): we don't use the transaction context because some
        # ports can belong to other projects.
        admin_context = n_context.get_admin_context()
        for port in qos_binding.QosPolicyPortBinding.get_ports_by_network_id(
                admin_context, network['id']):
            if (utils.is_network_device_port(port) or
                    utils.is_port_external(port)):
                continue

            self._update_port_qos_rules(txn, port['id'], network['id'],
                                        qos_policy_id, qos_rules)
            updated_port_ids.add(port['id'])

        fips = qos_binding.QosPolicyFloatingIPBinding.get_fips_by_network_id(
            admin_context, network['id'])
        fip_ids = [fip.id for fip in fips]
        for floatingip in self._plugin_l3.get_floatingips(
                admin_context, filters={'id': fip_ids}):
            self.update_floatingip(txn, floatingip)
            updated_fip_ids.add(floatingip['id'])

        for router in (qos_binding.QosPolicyRouterGatewayIPBinding.
                get_routers_by_network_id(admin_context, network['id'])):
            router_dict = self._plugin_l3._make_router_dict(router)
            self.update_router(txn, router_dict)
            updated_router_ids.add(router.id)

        return updated_port_ids, updated_fip_ids, updated_router_ids

    def _delete_fip_qos_rules(self, txn, fip_id, network_id):
        if network_id:
            lswitch_name = utils.ovn_name(network_id)
            txn.add(self.nb_idl.qos_del_ext_ids(
                lswitch_name,
                {ovn_const.OVN_FIP_EXT_ID_KEY: fip_id}))

    def create_floatingip(self, txn, floatingip):
        self.update_floatingip(txn, floatingip)

    def update_floatingip(self, txn, floatingip):
        router_id = floatingip.get('router_id')
        qos_policy_id = (floatingip.get('qos_policy_id') or
                         floatingip.get('qos_network_policy_id'))

        if not (router_id and qos_policy_id):
            return self._delete_fip_qos_rules(
                txn, floatingip['id'], floatingip['floating_network_id'])

        admin_context = n_context.get_admin_context()
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
            # "delete=not rule": that means, when we don't have rules, we
            # generate a "ovn_rule" to be used as input in a "qos_del" method.
            ovn_rule = self._ovn_qos_rule(
                direction, rules, gw_port_id,
                floatingip['floating_network_id'], fip_id=floatingip['id'],
                ip_address=floatingip['floating_ip_address'],
                resident_port=resident_port, delete=not rules)
            if rules:
                # NOTE(ralonsoh): with "may_exist=True", the "qos_add" will
                # create the QoS OVN rule or update the existing one.
                txn.add(self.nb_idl.qos_add(**ovn_rule, may_exist=True))
            else:
                # Delete, if exists, the QoS rule in this direction.
                txn.add(self.nb_idl.qos_del(**ovn_rule, if_exists=True))

    def delete_floatingip(self, txn, floatingip):
        self.update_floatingip(txn, floatingip)

    def disassociate_floatingip(self, txn, floatingip):
        self.delete_floatingip(txn, floatingip)

    def _delete_gateway_ip_qos_rules(self, txn, router_id, network_id):
        if network_id:
            lswitch_name = utils.ovn_name(network_id)
            txn.add(self.nb_idl.qos_del_ext_ids(
                lswitch_name,
                {ovn_const.OVN_ROUTER_ID_EXT_ID_KEY: router_id}))

    def create_router(self, txn, router):
        self.update_router(txn, router)

    def update_router(self, txn, router):
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

        admin_context = n_context.get_admin_context()
        qos_rules = self._qos_rules(admin_context, qos_policy_id)
        for direction, rules in qos_rules.items():
            # "delete=not rule": that means, when we don't have rules, we
            # generate a "ovn_rule" to be used as input in a "qos_del" method.
            ovn_rule = self._ovn_qos_rule(
                direction, rules, gw_port_id, gw_network_id,
                router_id=router_id, delete=not rules)
            if rules:
                # NOTE(ralonsoh): with "may_exist=True", the "qos_add" will
                # create the QoS OVN rule or update the existing one.
                txn.add(self.nb_idl.qos_add(**ovn_rule, may_exist=True))
            else:
                # Delete, if exists, the QoS rule in this direction.
                txn.add(self.nb_idl.qos_del(**ovn_rule, if_exists=True))

    def delete_router(self, txn, router):
        self._delete_gateway_ip_qos_rules(txn, router['id'],
                                          router['gw_network_id'])

    def update_policy(self, context, policy):
        updated_port_ids = set([])
        updated_fip_ids = set([])
        updated_router_ids = set([])
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
                network = {'qos_policy_id': policy.id, 'id': network_id}
                port_ids, fip_ids, router_ids = self.update_network(
                    txn, network, {}, reset=True, qos_rules=qos_rules)
                updated_port_ids.update(port_ids)
                updated_fip_ids.update(fip_ids)
                updated_router_ids.update(router_ids)

            # Update each port bound to this policy, not handled previously in
            # the network update loop
            port_ids = [p for p in bound_ports if p not in updated_port_ids]
            if port_ids:
                for port in self._plugin.get_ports(context,
                                                   filters={'id': port_ids}):
                    self.update_port(txn, port, {}, reset=True,
                                     qos_rules=qos_rules)

            # Update each FIP bound to this policy, not handled previously in
            # the network update loop
            fip_ids = [fip for fip in bound_fips if fip not in updated_fip_ids]
            if fip_ids:
                for fip in self._plugin_l3.get_floatingips(
                        context, filters={'id': fip_ids}):
                    self.update_floatingip(txn, fip)

            router_ids = [r for r in bound_routers if
                          r not in updated_router_ids]
            if router_ids:
                for router in self._plugin_l3.get_routers(
                        context, filters={'id': router_ids}):
                    self.update_router(txn, router)
