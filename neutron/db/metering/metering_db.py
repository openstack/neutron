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
from neutron_lib.exceptions import metering as metering_exc
from oslo_db import exception as db_exc
from oslo_utils import uuidutils

from neutron.api.rpc.agentnotifiers import metering_rpc_agent_api
from neutron.common import constants
from neutron.db import _utils as db_utils
from neutron.db import api as db_api
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_dvr_db
from neutron.db.models import metering as metering_models
from neutron.extensions import metering
from neutron.objects import base as base_obj
from neutron.objects import metering as metering_objs
from neutron.objects import router as l3_obj


class MeteringDbMixin(metering.MeteringPluginBase,
                      base_db.CommonDbMixin):

    def __init__(self):
        self.meter_rpc = metering_rpc_agent_api.MeteringAgentNotifyAPI()

    @staticmethod
    def _make_metering_label_dict(metering_label, fields=None):
        res = {'id': metering_label['id'],
               'name': metering_label['name'],
               'description': metering_label['description'],
               'shared': metering_label['shared'],
               'tenant_id': metering_label['tenant_id']}
        return db_utils.resource_fields(res, fields)

    def create_metering_label(self, context, metering_label):
        m = metering_label['metering_label']

        metering_obj = metering_objs.MeteringLabel(
            context, id=uuidutils.generate_uuid(),
            description=m['description'], project_id=m['tenant_id'],
            name=m['name'], shared=m['shared'])
        metering_obj.create()
        return self._make_metering_label_dict(metering_obj)

    def _get_metering_label(self, context, label_id):
        metering_label = metering_objs.MeteringLabel.get_object(context,
                                                                id=label_id)
        if not metering_label:
            raise metering_exc.MeteringLabelNotFound(label_id=label_id)
        return metering_label

    def delete_metering_label(self, context, label_id):
        deleted = metering_objs.MeteringLabel.delete_objects(
            context, id=label_id)
        if not deleted:
            raise metering_exc.MeteringLabelNotFound(label_id=label_id)

    def get_metering_label(self, context, label_id, fields=None):
        return self._make_metering_label_dict(
            self._get_metering_label(context, label_id), fields)

    def get_metering_labels(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        metering_labels = metering_objs.MeteringLabel.get_objects(context,
                                                                  _pager=pager,
                                                                  **filters)
        return [self._make_metering_label_dict(ml) for ml in metering_labels]

    @staticmethod
    def _make_metering_label_rule_dict(metering_label_rule, fields=None):
        res = {'id': metering_label_rule['id'],
               'metering_label_id': metering_label_rule['metering_label_id'],
               'direction': metering_label_rule['direction'],
               'remote_ip_prefix': metering_label_rule['remote_ip_prefix'],
               'excluded': metering_label_rule['excluded']}
        return db_utils.resource_fields(res, fields)

    def get_metering_label_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        metering_label_rules = metering_objs.MeteringLabelRule.get_objects(
            context, _pager=pager, **filters)
        return [self._make_metering_label_rule_dict(mlr)
                for mlr in metering_label_rules]

    def _get_metering_label_rule(self, context, rule_id):
        metering_label_rule = metering_objs.MeteringLabelRule.get_object(
            context, id=rule_id)
        if not metering_label_rule:
            raise metering_exc.MeteringLabelRuleNotFound(rule_id=rule_id)
        return metering_label_rule

    def get_metering_label_rule(self, context, rule_id, fields=None):
        return self._make_metering_label_rule_dict(
            self._get_metering_label_rule(context, rule_id), fields)

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
            raise metering_exc.MeteringLabelRuleOverlaps(
                remote_ip_prefix=remote_ip_prefix)

    def create_metering_label_rule(self, context, metering_label_rule):
        m = metering_label_rule['metering_label_rule']
        try:
            with db_api.context_manager.writer.using(context):
                label_id = m['metering_label_id']
                ip_prefix = m['remote_ip_prefix']
                direction = m['direction']
                excluded = m['excluded']

                self._validate_cidr(context, label_id, ip_prefix, direction,
                                    excluded)
                rule = metering_objs.MeteringLabelRule(
                    context, id=uuidutils.generate_uuid(),
                    metering_label_id=label_id, direction=direction,
                    excluded=m['excluded'],
                    remote_ip_prefix=netaddr.IPNetwork(ip_prefix))
                rule.create()
        except db_exc.DBReferenceError:
            raise metering_exc.MeteringLabelNotFound(label_id=label_id)

        return self._make_metering_label_rule_dict(rule)

    def delete_metering_label_rule(self, context, rule_id):
        with db_api.context_manager.writer.using(context):
            rule = self._get_metering_label_rule(context, rule_id)
            rule.delete()

        return self._make_metering_label_rule_dict(rule)

    def _get_metering_rules_dict(self, metering_label):
        rules = []
        for rule in metering_label.rules:
            rule_dict = self._make_metering_label_rule_dict(rule)
            rules.append(rule_dict)

        return rules

    def _make_router_dict(self, router):
        distributed = l3_dvr_db.is_distributed_router(router)
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               'gw_port_id': router['gw_port_id'],
               'distributed': distributed,
               constants.METERING_LABEL_KEY: []}

        return res

    def _process_sync_metering_data(self, context, labels):
        routers = None

        routers_dict = {}
        for label in labels:
            if label.shared:
                if not routers:
                    routers = l3_obj.Router.get_objects(context)
            else:
                routers = label.routers

            for router in routers:
                if not router['admin_state_up']:
                    continue
                router_dict = routers_dict.get(
                    router['id'],
                    self._make_router_dict(router))

                rules = self._get_metering_rules_dict(label)

                data = {'id': label['id'], 'rules': rules}
                router_dict[constants.METERING_LABEL_KEY].append(data)

                routers_dict[router['id']] = router_dict

        return list(routers_dict.values())

    def get_sync_data_for_rule(self, context, rule):
        label = context.session.query(
            metering_models.MeteringLabel).get(
                rule['metering_label_id'])

        if label.shared:
            routers = l3_obj.Router.get_objects(context)
        else:
            routers = label.routers

        routers_dict = {}
        for router in routers:
            router_dict = routers_dict.get(router['id'],
                                           self._make_router_dict(router))
            data = {'id': label['id'], 'rule': rule}
            router_dict[constants.METERING_LABEL_KEY].append(data)
            routers_dict[router['id']] = router_dict

        return list(routers_dict.values())

    def get_sync_data_metering(self, context, label_id=None):
        labels = context.session.query(metering_models.MeteringLabel)

        if label_id:
            labels = labels.filter(
                metering_models.MeteringLabel.id == label_id)

        return self._process_sync_metering_data(context, labels)
