# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.
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
#
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import firewall
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as const


LOG = logging.getLogger(__name__)


class FirewallRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall rule."""
    __tablename__ = 'firewall_rules'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(40))
    ip_version = sa.Column(sa.Integer, nullable=False)
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
    action = sa.Column(sa.Enum('allow', 'deny', name='firewallrules_action'))
    enabled = sa.Column(sa.Boolean)
    position = sa.Column(sa.Integer)


class Firewall(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall resource."""
    __tablename__ = 'firewalls'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(16))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)


class FirewallPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall Policy resource."""
    __tablename__ = 'firewall_policies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    firewall_rules = orm.relationship(
        FirewallRule,
        backref=orm.backref('firewall_policies', cascade='all, delete'),
        order_by='FirewallRule.position',
        collection_class=ordering_list('position', count_from=1))
    audited = sa.Column(sa.Boolean)
    firewalls = orm.relationship(Firewall, backref='firewall_policies')


class Firewall_db_mixin(firewall.FirewallPluginBase, base_db.CommonDbMixin):
    """Mixin class for Firewall DB implementation."""

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_firewall(self, context, id):
        try:
            return self._get_by_id(context, Firewall, id)
        except exc.NoResultFound:
            raise firewall.FirewallNotFound(firewall_id=id)

    def _get_firewall_policy(self, context, id):
        try:
            return self._get_by_id(context, FirewallPolicy, id)
        except exc.NoResultFound:
            raise firewall.FirewallPolicyNotFound(firewall_policy_id=id)

    def _get_firewall_rule(self, context, id):
        try:
            return self._get_by_id(context, FirewallRule, id)
        except exc.NoResultFound:
            raise firewall.FirewallRuleNotFound(firewall_rule_id=id)

    def _make_firewall_dict(self, fw, fields=None):
        res = {'id': fw['id'],
               'tenant_id': fw['tenant_id'],
               'name': fw['name'],
               'description': fw['description'],
               'shared': fw['shared'],
               'admin_state_up': fw['admin_state_up'],
               'status': fw['status'],
               'firewall_policy_id': fw['firewall_policy_id']}
        return self._fields(res, fields)

    def _make_firewall_policy_dict(self, firewall_policy, fields=None):
        fw_rules = [rule['id'] for rule in firewall_policy['firewall_rules']]
        firewalls = [fw['id'] for fw in firewall_policy['firewalls']]
        res = {'id': firewall_policy['id'],
               'tenant_id': firewall_policy['tenant_id'],
               'name': firewall_policy['name'],
               'description': firewall_policy['description'],
               'shared': firewall_policy['shared'],
               'audited': firewall_policy['audited'],
               'firewall_rules': fw_rules,
               'firewall_list': firewalls}
        return self._fields(res, fields)

    def _make_firewall_rule_dict(self, firewall_rule, fields=None):
        position = None
        # We return the position only if the firewall_rule is bound to a
        # firewall_policy.
        if firewall_rule['firewall_policy_id']:
            position = firewall_rule['position']
        src_port_range = self._get_port_range_from_min_max_ports(
            firewall_rule['source_port_range_min'],
            firewall_rule['source_port_range_max'])
        dst_port_range = self._get_port_range_from_min_max_ports(
            firewall_rule['destination_port_range_min'],
            firewall_rule['destination_port_range_max'])
        res = {'id': firewall_rule['id'],
               'tenant_id': firewall_rule['tenant_id'],
               'name': firewall_rule['name'],
               'description': firewall_rule['description'],
               'firewall_policy_id': firewall_rule['firewall_policy_id'],
               'shared': firewall_rule['shared'],
               'protocol': firewall_rule['protocol'],
               'ip_version': firewall_rule['ip_version'],
               'source_ip_address': firewall_rule['source_ip_address'],
               'destination_ip_address':
               firewall_rule['destination_ip_address'],
               'source_port': src_port_range,
               'destination_port': dst_port_range,
               'action': firewall_rule['action'],
               'position': position,
               'enabled': firewall_rule['enabled']}
        return self._fields(res, fields)

    def _set_rules_for_policy(self, context, firewall_policy_db, rule_id_list):
        fwp_db = firewall_policy_db
        with context.session.begin(subtransactions=True):
            if not rule_id_list:
                fwp_db.firewall_rules = []
                fwp_db.audited = False
                return
            # We will first check if the new list of rules is valid
            filters = {'id': [r_id for r_id in rule_id_list]}
            rules_in_db = self._get_collection_query(context, FirewallRule,
                                                     filters=filters)
            rules_dict = dict((fwr_db['id'], fwr_db) for fwr_db in rules_in_db)
            for fwrule_id in rule_id_list:
                if fwrule_id not in rules_dict:
                    # If we find an invalid rule in the list we
                    # do not perform the update since this breaks
                    # the integrity of this list.
                    raise firewall.FirewallRuleNotFound(firewall_rule_id=
                                                        fwrule_id)
                elif rules_dict[fwrule_id]['firewall_policy_id']:
                    if (rules_dict[fwrule_id]['firewall_policy_id'] !=
                            fwp_db['id']):
                        raise firewall.FirewallRuleInUse(
                            firewall_rule_id=fwrule_id)
            # New list of rules is valid so we will first reset the existing
            # list and then add each rule in order.
            # Note that the list could be empty in which case we interpret
            # it as clearing existing rules.
            fwp_db.firewall_rules = []
            for fwrule_id in rule_id_list:
                fwp_db.firewall_rules.append(rules_dict[fwrule_id])
            fwp_db.firewall_rules.reorder()
            fwp_db.audited = False

    def _process_rule_for_policy(self, context, firewall_policy_id,
                                 firewall_rule_db, position):
        with context.session.begin(subtransactions=True):
            fwp_query = context.session.query(
                FirewallPolicy).with_lockmode('update')
            fwp_db = fwp_query.filter_by(id=firewall_policy_id).one()
            if position:
                # Note that although position numbering starts at 1,
                # internal ordering of the list starts at 0, so we compensate.
                fwp_db.firewall_rules.insert(position - 1, firewall_rule_db)
            else:
                fwp_db.firewall_rules.remove(firewall_rule_db)
            fwp_db.firewall_rules.reorder()
            fwp_db.audited = False
        return self._make_firewall_policy_dict(fwp_db)

    def _get_min_max_ports_from_range(self, port_range):
        if not port_range:
            return [None, None]
        min_port, sep, max_port = port_range.partition(":")
        if not max_port:
            max_port = min_port
        return [int(min_port), int(max_port)]

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        else:
            return '%d:%d' % (min_port, max_port)

    def create_firewall(self, context, firewall):
        LOG.debug(_("create_firewall() called"))
        fw = firewall['firewall']
        tenant_id = self._get_tenant_id_for_create(context, fw)
        with context.session.begin(subtransactions=True):
            firewall_db = Firewall(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=fw['name'],
                                   description=fw['description'],
                                   firewall_policy_id=
                                   fw['firewall_policy_id'],
                                   admin_state_up=fw['admin_state_up'],
                                   status=const.PENDING_CREATE)
            context.session.add(firewall_db)
        return self._make_firewall_dict(firewall_db)

    def update_firewall(self, context, id, firewall):
        LOG.debug(_("update_firewall() called"))
        fw = firewall['firewall']
        with context.session.begin(subtransactions=True):
            fw_query = context.session.query(
                Firewall).with_lockmode('update')
            firewall_db = fw_query.filter_by(id=id).one()
            firewall_db.update(fw)
        return self._make_firewall_dict(firewall_db)

    def delete_firewall(self, context, id):
        LOG.debug(_("delete_firewall() called"))
        with context.session.begin(subtransactions=True):
            fw_query = context.session.query(
                Firewall).with_lockmode('update')
            firewall_db = fw_query.filter_by(id=id).one()
            # Note: Plugin should ensure that it's okay to delete if the
            # firewall is active
            context.session.delete(firewall_db)

    def get_firewall(self, context, id, fields=None):
        LOG.debug(_("get_firewall() called"))
        fw = self._get_firewall(context, id)
        return self._make_firewall_dict(fw, fields)

    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug(_("get_firewalls() called"))
        return self._get_collection(context, Firewall,
                                    self._make_firewall_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_count(self, context, filters=None):
        LOG.debug(_("get_firewalls_count() called"))
        return self._get_collection_count(context, Firewall,
                                          filters=filters)

    def create_firewall_policy(self, context, firewall_policy):
        LOG.debug(_("create_firewall_policy() called"))
        fwp = firewall_policy['firewall_policy']
        tenant_id = self._get_tenant_id_for_create(context, fwp)
        with context.session.begin(subtransactions=True):
            fwp_db = FirewallPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=fwp['name'],
                                    description=fwp['description'],
                                    shared=fwp['shared'])
            context.session.add(fwp_db)
            self._set_rules_for_policy(context, fwp_db,
                                       fwp['firewall_rules'])
            fwp_db.audited = fwp['audited']
        return self._make_firewall_policy_dict(fwp_db)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug(_("update_firewall_policy() called"))
        fwp = firewall_policy['firewall_policy']
        with context.session.begin(subtransactions=True):
            fwp_db = self._get_firewall_policy(context, id)
            if 'firewall_rules' in fwp:
                self._set_rules_for_policy(context, fwp_db,
                                           fwp['firewall_rules'])
                del fwp['firewall_rules']
            fwp_db.update(fwp)
        return self._make_firewall_policy_dict(fwp_db)

    def delete_firewall_policy(self, context, id):
        LOG.debug(_("delete_firewall_policy() called"))
        with context.session.begin(subtransactions=True):
            fwp = self._get_firewall_policy(context, id)
            # Ensure that the firewall_policy  is not
            # being used
            qry = context.session.query(Firewall)
            if qry.filter_by(firewall_policy_id=id).first():
                raise firewall.FirewallPolicyInUse(firewall_policy_id=id)
            else:
                context.session.delete(fwp)

    def get_firewall_policy(self, context, id, fields=None):
        LOG.debug(_("get_firewall_policy() called"))
        fwp = self._get_firewall_policy(context, id)
        return self._make_firewall_policy_dict(fwp, fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        LOG.debug(_("get_firewall_policies() called"))
        return self._get_collection(context, FirewallPolicy,
                                    self._make_firewall_policy_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_policies_count(self, context, filters=None):
        LOG.debug(_("get_firewall_policies_count() called"))
        return self._get_collection_count(context, FirewallPolicy,
                                          filters=filters)

    def create_firewall_rule(self, context, firewall_rule):
        LOG.debug(_("create_firewall_rule() called"))
        fwr = firewall_rule['firewall_rule']
        tenant_id = self._get_tenant_id_for_create(context, fwr)
        if not fwr['protocol'] and (fwr['source_port'] or
                                    fwr['destination_port']):
            raise firewall.FirewallRuleWithPortWithoutProtocolInvalid()
        src_port_min, src_port_max = self._get_min_max_ports_from_range(
            fwr['source_port'])
        dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
            fwr['destination_port'])
        with context.session.begin(subtransactions=True):
            fwr_db = FirewallRule(id=uuidutils.generate_uuid(),
                                  tenant_id=tenant_id,
                                  name=fwr['name'],
                                  description=fwr['description'],
                                  shared=fwr['shared'],
                                  protocol=fwr['protocol'],
                                  ip_version=fwr['ip_version'],
                                  source_ip_address=fwr['source_ip_address'],
                                  destination_ip_address=
                                  fwr['destination_ip_address'],
                                  source_port_range_min=src_port_min,
                                  source_port_range_max=src_port_max,
                                  destination_port_range_min=dst_port_min,
                                  destination_port_range_max=dst_port_max,
                                  action=fwr['action'],
                                  enabled=fwr['enabled'])
            context.session.add(fwr_db)
        return self._make_firewall_rule_dict(fwr_db)

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug(_("update_firewall_rule() called"))
        fwr = firewall_rule['firewall_rule']
        if 'source_port' in fwr:
            src_port_min, src_port_max = self._get_min_max_ports_from_range(
                fwr['source_port'])
            fwr['source_port_range_min'] = src_port_min
            fwr['source_port_range_max'] = src_port_max
            del fwr['source_port']
        if 'destination_port' in fwr:
            dst_port_min, dst_port_max = self._get_min_max_ports_from_range(
                fwr['destination_port'])
            fwr['destination_port_range_min'] = dst_port_min
            fwr['destination_port_range_max'] = dst_port_max
            del fwr['destination_port']
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, id)
            protocol = fwr.get('protocol', fwr_db['protocol'])
            if not protocol:
                sport = fwr.get('source_port_range_min',
                                fwr_db['source_port_range_min'])
                dport = fwr.get('destination_port_range_min',
                                fwr_db['destination_port_range_min'])
                if sport or dport:
                    raise firewall.FirewallRuleWithPortWithoutProtocolInvalid()
            fwr_db.update(fwr)
            if fwr_db.firewall_policy_id:
                fwp_db = self._get_firewall_policy(context,
                                                   fwr_db.firewall_policy_id)
                fwp_db.audited = False
        return self._make_firewall_rule_dict(fwr_db)

    def delete_firewall_rule(self, context, id):
        LOG.debug(_("delete_firewall_rule() called"))
        with context.session.begin(subtransactions=True):
            fwr = self._get_firewall_rule(context, id)
            if fwr.firewall_policy_id:
                raise firewall.FirewallRuleInUse(firewall_rule_id=id)
            context.session.delete(fwr)

    def get_firewall_rule(self, context, id, fields=None):
        LOG.debug(_("get_firewall_rule() called"))
        fwr = self._get_firewall_rule(context, id)
        return self._make_firewall_rule_dict(fwr, fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        LOG.debug(_("get_firewall_rules() called"))
        return self._get_collection(context, FirewallRule,
                                    self._make_firewall_rule_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_rules_count(self, context, filters=None):
        LOG.debug(_("get_firewall_rules_count() called"))
        return self._get_collection_count(context, FirewallRule,
                                          filters=filters)

    def _validate_insert_remove_rule_request(self, id, rule_info):
        if not rule_info or 'firewall_rule_id' not in rule_info:
            raise firewall.FirewallRuleInfoMissing()

    def insert_rule(self, context, id, rule_info):
        LOG.debug(_("insert_rule() called"))
        self._validate_insert_remove_rule_request(id, rule_info)
        firewall_rule_id = rule_info['firewall_rule_id']
        insert_before = True
        ref_firewall_rule_id = None
        if not firewall_rule_id:
            raise firewall.FirewallRuleNotFound(firewall_rule_id=None)
        if 'insert_before' in rule_info:
            ref_firewall_rule_id = rule_info['insert_before']
        if not ref_firewall_rule_id and 'insert_after' in rule_info:
            # If insert_before is set, we will ignore insert_after.
            ref_firewall_rule_id = rule_info['insert_after']
            insert_before = False
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, firewall_rule_id)
            if fwr_db.firewall_policy_id:
                raise firewall.FirewallRuleInUse(firewall_rule_id=fwr_db['id'])
            if ref_firewall_rule_id:
                # If reference_firewall_rule_id is set, the new rule
                # is inserted depending on the value of insert_before.
                # If insert_before is set, the new rule is inserted before
                # reference_firewall_rule_id, and if it is not set the new
                # rule is inserted after reference_firewall_rule_id.
                ref_fwr_db = self._get_firewall_rule(
                    context, ref_firewall_rule_id)
                if insert_before:
                    position = ref_fwr_db.position
                else:
                    position = ref_fwr_db.position + 1
            else:
                # If reference_firewall_rule_id is not set, it is assumed
                # that the new rule needs to be inserted at the top.
                # insert_before field is ignored.
                # So default insertion is always at the top.
                # Also note that position numbering starts at 1.
                position = 1
            return self._process_rule_for_policy(context, id, fwr_db,
                                                 position)

    def remove_rule(self, context, id, rule_info):
        LOG.debug(_("remove_rule() called"))
        self._validate_insert_remove_rule_request(id, rule_info)
        firewall_rule_id = rule_info['firewall_rule_id']
        if not firewall_rule_id:
            raise firewall.FirewallRuleNotFound(firewall_rule_id=None)
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, firewall_rule_id)
            if fwr_db.firewall_policy_id != id:
                raise firewall.FirewallRuleNotAssociatedWithPolicy(
                    firewall_rule_id=fwr_db['id'],
                    firewall_policy_id=id)
            return self._process_rule_for_policy(context, id, fwr_db, None)
