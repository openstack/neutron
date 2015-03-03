# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import netaddr
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.api.rpc.agentnotifiers import metering_rpc_agent_api
from neutron.common import constants
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import metering


LOG = logging.getLogger(__name__)


class MeteringLabelRule(model_base.BASEV2, models_v2.HasId):
    direction = sa.Column(sa.Enum('ingress', 'egress',
                                  name='meteringlabels_direction'))
    remote_ip_prefix = sa.Column(sa.String(64))
    metering_label_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("meteringlabels.id",
                                                ondelete="CASCADE"),
                                  nullable=False)
    excluded = sa.Column(sa.Boolean, default=False, server_default=sql.false())


class MeteringLabel(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    rules = orm.relationship(MeteringLabelRule, backref="label",
                             cascade="delete", lazy="joined")
    routers = orm.relationship(
        l3_db.Router,
        primaryjoin="MeteringLabel.tenant_id==Router.tenant_id",
        foreign_keys='MeteringLabel.tenant_id',
        uselist=True)
    shared = sa.Column(sa.Boolean, default=False, server_default=sql.false())


class MeteringDbMixin(metering.MeteringPluginBase,
                      base_db.CommonDbMixin):

    def __init__(self):
        self.meter_rpc = metering_rpc_agent_api.MeteringAgentNotifyAPI()

    def _make_metering_label_dict(self, metering_label, fields=None):
        res = {'id': metering_label['id'],
               'name': metering_label['name'],
               'description': metering_label['description'],
               'shared': metering_label['shared'],
               'tenant_id': metering_label['tenant_id']}
        return self._fields(res, fields)

    def create_metering_label(self, context, metering_label):
        m = metering_label['metering_label']
        tenant_id = self._get_tenant_id_for_create(context, m)

        with context.session.begin(subtransactions=True):
            metering_db = MeteringLabel(id=uuidutils.generate_uuid(),
                                        description=m['description'],
                                        tenant_id=tenant_id,
                                        name=m['name'],
                                        shared=m['shared'])
            context.session.add(metering_db)

        return self._make_metering_label_dict(metering_db)

    def delete_metering_label(self, context, label_id):
        with context.session.begin(subtransactions=True):
            try:
                label = self._get_by_id(context, MeteringLabel, label_id)
            except orm.exc.NoResultFound:
                raise metering.MeteringLabelNotFound(label_id=label_id)

            context.session.delete(label)

    def get_metering_label(self, context, label_id, fields=None):
        try:
            metering_label = self._get_by_id(context, MeteringLabel, label_id)
        except orm.exc.NoResultFound:
            raise metering.MeteringLabelNotFound(label_id=label_id)

        return self._make_metering_label_dict(metering_label, fields)

    def get_metering_labels(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'metering_labels', limit,
                                          marker)
        return self._get_collection(context, MeteringLabel,
                                    self._make_metering_label_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def _make_metering_label_rule_dict(self, metering_label_rule, fields=None):
        res = {'id': metering_label_rule['id'],
               'metering_label_id': metering_label_rule['metering_label_id'],
               'direction': metering_label_rule['direction'],
               'remote_ip_prefix': metering_label_rule['remote_ip_prefix'],
               'excluded': metering_label_rule['excluded']}
        return self._fields(res, fields)

    def get_metering_label_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'metering_label_rules',
                                          limit, marker)

        return self._get_collection(context, MeteringLabelRule,
                                    self._make_metering_label_rule_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_metering_label_rule(self, context, rule_id, fields=None):
        try:
            metering_label_rule = self._get_by_id(context,
                                                  MeteringLabelRule, rule_id)
        except orm.exc.NoResultFound:
            raise metering.MeteringLabelRuleNotFound(rule_id=rule_id)

        return self._make_metering_label_rule_dict(metering_label_rule, fields)

    def _validate_cidr(self, context, label_id, remote_ip_prefix,
                       direction, excluded):
        r_ips = self.get_metering_label_rules(context,
                                              filters={'metering_label_id':
                                                       [label_id],
                                                       'direction':
                                                       [direction],
                                                       'excluded':
                                                       [excluded]},
                                              fields=['remote_ip_prefix'])

        cidrs = [r['remote_ip_prefix'] for r in r_ips]
        new_cidr_ipset = netaddr.IPSet([remote_ip_prefix])
        if (netaddr.IPSet(cidrs) & new_cidr_ipset):
            raise metering.MeteringLabelRuleOverlaps(
                remote_ip_prefix=remote_ip_prefix)

    def create_metering_label_rule(self, context, metering_label_rule):
        m = metering_label_rule['metering_label_rule']
        with context.session.begin(subtransactions=True):
            label_id = m['metering_label_id']
            ip_prefix = m['remote_ip_prefix']
            direction = m['direction']
            excluded = m['excluded']

            self._validate_cidr(context, label_id, ip_prefix, direction,
                                excluded)
            metering_db = MeteringLabelRule(id=uuidutils.generate_uuid(),
                                            metering_label_id=label_id,
                                            direction=direction,
                                            excluded=m['excluded'],
                                            remote_ip_prefix=ip_prefix)
            context.session.add(metering_db)

        return self._make_metering_label_rule_dict(metering_db)

    def delete_metering_label_rule(self, context, rule_id):
        with context.session.begin(subtransactions=True):
            try:
                rule = self._get_by_id(context, MeteringLabelRule, rule_id)
            except orm.exc.NoResultFound:
                raise metering.MeteringLabelRuleNotFound(rule_id=rule_id)
            context.session.delete(rule)

        return self._make_metering_label_rule_dict(rule)

    def _get_metering_rules_dict(self, metering_label):
        rules = []
        for rule in metering_label.rules:
            rule_dict = self._make_metering_label_rule_dict(rule)
            rules.append(rule_dict)

        return rules

    def _make_router_dict(self, router):
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               'gw_port_id': router['gw_port_id'],
               constants.METERING_LABEL_KEY: []}

        return res

    def _process_sync_metering_data(self, context, labels):
        all_routers = None

        routers_dict = {}
        for label in labels:
            if label.shared:
                if not all_routers:
                    all_routers = self._get_collection_query(context,
                                                             l3_db.Router)
                routers = all_routers
            else:
                routers = label.routers

            for router in routers:
                router_dict = routers_dict.get(
                    router['id'],
                    self._make_router_dict(router))

                rules = self._get_metering_rules_dict(label)

                data = {'id': label['id'], 'rules': rules}
                router_dict[constants.METERING_LABEL_KEY].append(data)

                routers_dict[router['id']] = router_dict

        return routers_dict.values()

    def get_sync_data_for_rule(self, context, rule):
        label = context.session.query(MeteringLabel).get(
            rule['metering_label_id'])

        if label.shared:
            routers = self._get_collection_query(context, l3_db.Router)
        else:
            routers = label.routers

        routers_dict = {}
        for router in routers:
            router_dict = routers_dict.get(router['id'],
                                           self._make_router_dict(router))
            data = {'id': label['id'], 'rule': rule}
            router_dict[constants.METERING_LABEL_KEY].append(data)
            routers_dict[router['id']] = router_dict

        return routers_dict.values()

    def get_sync_data_metering(self, context, label_id=None, router_ids=None):
        labels = context.session.query(MeteringLabel)

        if label_id:
            labels = labels.filter(MeteringLabel.id == label_id)
        elif router_ids:
            labels = (labels.join(MeteringLabel.routers).
                      filter(l3_db.Router.id.in_(router_ids)))

        return self._process_sync_metering_data(context, labels)
