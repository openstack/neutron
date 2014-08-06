# Copyright 2013 VMware, Inc
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

from neutron.db import db_base_plugin_v2
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.plugins.vmware.dbexts import vcns_db
from neutron.plugins.vmware.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)

VSE_FWAAS_ALLOW = "accept"
VSE_FWAAS_DENY = "deny"


class EdgeFirewallDriver(db_base_plugin_v2.NeutronDbPluginV2):
    """Implementation of driver APIs for
       Edge Firewall feature configuration
    """
    def _convert_firewall_action(self, action):
        if action == constants.FWAAS_ALLOW:
            return VSE_FWAAS_ALLOW
        elif action == constants.FWAAS_DENY:
            return VSE_FWAAS_DENY
        else:
            msg = _("Invalid action value %s in a firewall rule") % action
            raise vcns_exc.VcnsBadRequest(resource='firewall_rule', msg=msg)

    def _restore_firewall_action(self, action):
        if action == VSE_FWAAS_ALLOW:
            return constants.FWAAS_ALLOW
        elif action == VSE_FWAAS_DENY:
            return constants.FWAAS_DENY
        else:
            msg = (_("Invalid action value %s in "
                     "a vshield firewall rule") % action)
            raise vcns_exc.VcnsBadRequest(resource='firewall_rule', msg=msg)

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        else:
            return '%d:%d' % (min_port, max_port)

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        return [int(min_port), int(max_port)]

    def _convert_firewall_rule(self, context, rule, index=None):
        vcns_rule = {
            "name": rule['name'],
            "description": rule['description'],
            "action": self._convert_firewall_action(rule['action']),
            "enabled": rule['enabled']}
        if rule.get('source_ip_address'):
            vcns_rule['source'] = {
                "ipAddress": [rule['source_ip_address']]
            }
        if rule.get('destination_ip_address'):
            vcns_rule['destination'] = {
                "ipAddress": [rule['destination_ip_address']]
            }
        service = {}
        if rule.get('source_port'):
            min_port, max_port = self._get_min_max_ports_from_range(
                rule['source_port'])
            service['sourcePort'] = [i for i in range(min_port, max_port + 1)]
        if rule.get('destination_port'):
            min_port, max_port = self._get_min_max_ports_from_range(
                rule['destination_port'])
            service['port'] = [i for i in range(min_port, max_port + 1)]
        if rule.get('protocol'):
            service['protocol'] = rule['protocol']
        if service:
            vcns_rule['application'] = {
                'service': [service]
            }
        if index:
            vcns_rule['ruleTag'] = index
        return vcns_rule

    def _restore_firewall_rule(self, context, edge_id, response):
        rule = response
        rule_binding = vcns_db.get_vcns_edge_firewallrule_binding_by_vseid(
            context.session, edge_id, rule['ruleId'])
        service = rule['application']['service'][0]
        src_port_range = self._get_port_range_from_min_max_ports(
            service['sourcePort'][0], service['sourcePort'][-1])
        dst_port_range = self._get_port_range_from_min_max_ports(
            service['port'][0], service['port'][-1])
        return {
            'firewall_rule': {
                'name': rule['name'],
                'id': rule_binding['rule_id'],
                'description': rule['description'],
                'source_ip_address': rule['source']['ipAddress'][0],
                'destination_ip_address': rule['destination']['ipAddress'][0],
                'protocol': service['protocol'],
                'destination_port': dst_port_range,
                'source_port': src_port_range,
                'action': self._restore_firewall_action(rule['action']),
                'enabled': rule['enabled']}}

    def _convert_firewall(self, context, firewall):
        #bulk configuration on firewall and rescheduling the rule binding
        ruleTag = 1
        vcns_rules = []
        for rule in firewall['firewall_rule_list']:
            vcns_rule = self._convert_firewall_rule(context, rule, ruleTag)
            vcns_rules.append(vcns_rule)
            ruleTag += 1
        return {
            'featureType': "firewall_4.0",
            'firewallRules': {
                'firewallRules': vcns_rules}}

    def _restore_firewall(self, context, edge_id, response):
        res = {}
        res['firewall_rule_list'] = []
        for rule in response['firewallRules']['firewallRules']:
            rule_binding = (
                vcns_db.get_vcns_edge_firewallrule_binding_by_vseid(
                    context.session, edge_id, rule['ruleId']))
            if rule_binding is None:
                continue
            service = rule['application']['service'][0]
            src_port_range = self._get_port_range_from_min_max_ports(
                service['sourcePort'][0], service['sourcePort'][-1])
            dst_port_range = self._get_port_range_from_min_max_ports(
                service['port'][0], service['port'][-1])
            item = {
                'firewall_rule': {
                    'name': rule['name'],
                    'id': rule_binding['rule_id'],
                    'description': rule['description'],
                    'source_ip_address': rule['source']['ipAddress'][0],
                    'destination_ip_address': rule[
                        'destination']['ipAddress'][0],
                    'protocol': service['protocol'],
                    'destination_port': dst_port_range,
                    'source_port': src_port_range,
                    'action': self._restore_firewall_action(rule['action']),
                    'enabled': rule['enabled']}}
            res['firewall_rule_list'].append(item)
        return res

    def _create_rule_id_mapping(
        self, context, edge_id, firewall, vcns_fw):
        for rule in vcns_fw['firewallRules']['firewallRules']:
            index = rule['ruleTag'] - 1
            #TODO(linb):a simple filter of the retrived rules which may be
            #created by other operations unintentionally
            if index < len(firewall['firewall_rule_list']):
                rule_vseid = rule['ruleId']
                rule_id = firewall['firewall_rule_list'][index]['id']
                map_info = {
                    'rule_id': rule_id,
                    'rule_vseid': rule_vseid,
                    'edge_id': edge_id
                }
                vcns_db.add_vcns_edge_firewallrule_binding(
                    context.session, map_info)

    def _get_firewall(self, context, edge_id):
        try:
            return self.vcns.get_firewall(edge_id)[1]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to get firewall with edge "
                                "id: %s"), edge_id)

    def _get_firewall_rule_next(self, context, edge_id, rule_vseid):
        # Return the firewall rule below 'rule_vseid'
        fw_cfg = self._get_firewall(context, edge_id)
        for i in range(len(fw_cfg['firewallRules']['firewallRules'])):
            rule_cur = fw_cfg['firewallRules']['firewallRules'][i]
            if str(rule_cur['ruleId']) == rule_vseid:
                if (i + 1) == len(fw_cfg['firewallRules']['firewallRules']):
                    return None
                else:
                    return fw_cfg['firewallRules']['firewallRules'][i + 1]

    def get_firewall_rule(self, context, id, edge_id):
        rule_map = vcns_db.get_vcns_edge_firewallrule_binding(
            context.session, id, edge_id)
        if rule_map is None:
            msg = _("No rule id:%s found in the edge_firewall_binding") % id
            LOG.error(msg)
            raise vcns_exc.VcnsNotFound(
                resource='vcns_firewall_rule_bindings', msg=msg)
        vcns_rule_id = rule_map.rule_vseid
        try:
            response = self.vcns.get_firewall_rule(
                edge_id, vcns_rule_id)[1]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to get firewall rule: %(rule_id)s "
                                "with edge_id: %(edge_id)s"), {
                                    'rule_id': id,
                                    'edge_id': edge_id})
        return self._restore_firewall_rule(context, edge_id, response)

    def get_firewall(self, context, edge_id):
        response = self._get_firewall(context, edge_id)
        return self._restore_firewall(context, edge_id, response)

    def update_firewall(self, context, edge_id, firewall):
        fw_req = self._convert_firewall(context, firewall)
        try:
            self.vcns.update_firewall(edge_id, fw_req)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update firewall "
                                "with edge_id: %s"), edge_id)
        fw_res = self._get_firewall(context, edge_id)
        vcns_db.cleanup_vcns_edge_firewallrule_binding(
            context.session, edge_id)
        self._create_rule_id_mapping(context, edge_id, firewall, fw_res)

    def delete_firewall(self, context, edge_id):
        try:
            self.vcns.delete_firewall(edge_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete firewall "
                                "with edge_id:%s"), edge_id)
        vcns_db.cleanup_vcns_edge_firewallrule_binding(
            context.session, edge_id)

    def update_firewall_rule(self, context, id, edge_id, firewall_rule):
        rule_map = vcns_db.get_vcns_edge_firewallrule_binding(
            context.session, id, edge_id)
        vcns_rule_id = rule_map.rule_vseid
        fwr_req = self._convert_firewall_rule(context, firewall_rule)
        try:
            self.vcns.update_firewall_rule(edge_id, vcns_rule_id, fwr_req)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to update firewall rule: %(rule_id)s "
                                "with edge_id: %(edge_id)s"),
                              {'rule_id': id,
                               'edge_id': edge_id})

    def delete_firewall_rule(self, context, id, edge_id):
        rule_map = vcns_db.get_vcns_edge_firewallrule_binding(
            context.session, id, edge_id)
        vcns_rule_id = rule_map.rule_vseid
        try:
            self.vcns.delete_firewall_rule(edge_id, vcns_rule_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to delete firewall rule: %(rule_id)s "
                                "with edge_id: %(edge_id)s"),
                              {'rule_id': id,
                               'edge_id': edge_id})
        vcns_db.delete_vcns_edge_firewallrule_binding(
            context.session, id, edge_id)

    def _add_rule_above(self, context, ref_rule_id, edge_id, firewall_rule):
        rule_map = vcns_db.get_vcns_edge_firewallrule_binding(
            context.session, ref_rule_id, edge_id)
        ref_vcns_rule_id = rule_map.rule_vseid
        fwr_req = self._convert_firewall_rule(context, firewall_rule)
        try:
            header = self.vcns.add_firewall_rule_above(
                edge_id, ref_vcns_rule_id, fwr_req)[0]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Failed to add firewall rule above: "
                                "%(rule_id)s with edge_id: %(edge_id)s"),
                              {'rule_id': ref_vcns_rule_id,
                               'edge_id': edge_id})

        objuri = header['location']
        fwr_vseid = objuri[objuri.rfind("/") + 1:]
        map_info = {
            'rule_id': firewall_rule['id'],
            'rule_vseid': fwr_vseid,
            'edge_id': edge_id}
        vcns_db.add_vcns_edge_firewallrule_binding(
            context.session, map_info)

    def _add_rule_below(self, context, ref_rule_id, edge_id, firewall_rule):
        rule_map = vcns_db.get_vcns_edge_firewallrule_binding(
            context.session, ref_rule_id, edge_id)
        ref_vcns_rule_id = rule_map.rule_vseid
        fwr_vse_next = self._get_firewall_rule_next(
            context, edge_id, ref_vcns_rule_id)
        fwr_req = self._convert_firewall_rule(context, firewall_rule)
        if fwr_vse_next:
            ref_vcns_rule_id = fwr_vse_next['ruleId']
            try:
                header = self.vcns.add_firewall_rule_above(
                    edge_id, int(ref_vcns_rule_id), fwr_req)[0]
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Failed to add firewall rule above: "
                                    "%(rule_id)s with edge_id: %(edge_id)s"),
                                  {'rule_id': ref_vcns_rule_id,
                                   'edge_id': edge_id})
        else:
            # append the rule at the bottom
            try:
                header = self.vcns.add_firewall_rule(
                    edge_id, fwr_req)[0]
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_("Failed to append a firewall rule"
                                    "with edge_id: %s"), edge_id)

        objuri = header['location']
        fwr_vseid = objuri[objuri.rfind("/") + 1:]
        map_info = {
            'rule_id': firewall_rule['id'],
            'rule_vseid': fwr_vseid,
            'edge_id': edge_id
        }
        vcns_db.add_vcns_edge_firewallrule_binding(
            context.session, map_info)

    def insert_rule(self, context, rule_info, edge_id, fwr):
        if rule_info.get('insert_before'):
            self._add_rule_above(
                context, rule_info['insert_before'], edge_id, fwr)
        elif rule_info.get('insert_after'):
            self._add_rule_below(
                context, rule_info['insert_after'], edge_id, fwr)
        else:
            msg = _("Can't execute insert rule operation "
                    "without reference rule_id")
            raise vcns_exc.VcnsBadRequest(resource='firewall_rule', msg=msg)
