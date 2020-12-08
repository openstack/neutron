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

import ipaddress

import netaddr

from neutron_lib.agent import topics
from neutron_lib.api.definitions import metering as metering_apidef
from neutron_lib.api.definitions import metering_source_and_destination_filters
from neutron_lib.exceptions import metering as metering_exc

from neutron_lib import exceptions as neutron_exc
from neutron_lib import rpc as n_rpc

from neutron.api.rpc.agentnotifiers import metering_rpc_agent_api
from neutron.db.metering import metering_db
from neutron.db.metering import metering_rpc
from neutron import service

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class MeteringPlugin(metering_db.MeteringDbMixin):
    """Implementation of the Neutron Metering Service Plugin."""
    supported_extension_aliases = [
        metering_apidef.ALIAS, metering_source_and_destination_filters.ALIAS]
    path_prefix = "/metering"
    __filter_validation_support = True

    def __init__(self):
        super(MeteringPlugin, self).__init__()

        self.meter_rpc = metering_rpc_agent_api.MeteringAgentNotifyAPI()
        rpc_worker = service.RpcWorker([self], worker_process_count=0)

        self.add_worker(rpc_worker)

    def start_rpc_listeners(self):
        self.endpoints = [metering_rpc.MeteringRpcCallbacks(self)]
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(
            topics.METERING_PLUGIN, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def create_metering_label(self, context, metering_label):
        label = super(MeteringPlugin, self).create_metering_label(
            context, metering_label)

        data = self.get_sync_data_metering(context)
        self.meter_rpc.add_metering_label(context, data)

        return label

    def delete_metering_label(self, context, label_id):
        data = self.get_sync_data_metering(context, label_id)
        super(MeteringPlugin, self).delete_metering_label(
            context, label_id)

        self.meter_rpc.remove_metering_label(context, data)

    def create_metering_label_rule(self, context, metering_label_rule):
        metering_label_rule = metering_label_rule['metering_label_rule']
        MeteringPlugin.validate_metering_label_rule(metering_label_rule)
        self.check_for_rule_overlaps(context, metering_label_rule)

        rule = super(MeteringPlugin, self).create_metering_label_rule(
            context, metering_label_rule)

        if rule.get("remote_ip_prefix"):
            LOG.warning("The use of 'remote_ip_prefix' in metering label "
                        "rules is deprecated and will be removed in future "
                        "releases. One should use instead the "
                        "'source_ip_prefix' and/or 'destination_ip_prefix' "
                        "parameters. For more details, you can check the "
                        "spec: https://review.opendev.org/#/c/744702/.")

        data = self.get_sync_data_for_rule(context, rule)
        self.meter_rpc.add_metering_label_rule(context, data)

        return rule

    @staticmethod
    def validate_metering_label_rule(metering_label_rule):
        MeteringPlugin.validate_metering_rule_ip_address(
            metering_label_rule, "remote_ip_prefix")
        MeteringPlugin.validate_metering_rule_ip_address(
            metering_label_rule, "source_ip_prefix")
        MeteringPlugin.validate_metering_rule_ip_address(
            metering_label_rule, "destination_ip_prefix")

        if metering_label_rule.get("remote_ip_prefix"):
            if metering_label_rule.get("source_ip_prefix") or \
                    metering_label_rule.get("destination_ip_prefix"):
                raise neutron_exc.Invalid(
                    "Cannot use 'remote-ip-prefix' in conjunction "
                    "with 'source-ip-prefix' or 'destination-ip-prefix'.")

        none_ip_prefix_informed = not metering_label_rule.get(
            'remote_ip_prefix') and not metering_label_rule.get(
            'source_ip_prefix') and not metering_label_rule.get(
            'destination_ip_prefix')

        if none_ip_prefix_informed:
            raise neutron_exc.Invalid(
                "You must define at least one of the following parameters "
                "'remote_ip_prefix', or 'source_ip_prefix' or "
                "'destination_ip_prefix'.")

    @staticmethod
    def validate_metering_rule_ip_address(metering_label_rule,
                                          ip_address_field):
        try:
            if metering_label_rule.get(ip_address_field):
                ipaddress.ip_interface(
                    metering_label_rule.get(ip_address_field))
        except ValueError as exception:
            raise neutron_exc.Invalid(
                "%s: %s is invalid [%s]." %
                (ip_address_field,
                 metering_label_rule.get(ip_address_field),
                 exception))

    def check_for_rule_overlaps(self, context, metering_label_rule):
        label_id = metering_label_rule['metering_label_id']
        direction = metering_label_rule['direction']
        excluded = metering_label_rule['excluded']

        db_metering_rules = self.get_metering_label_rules(
            context, filters={
                'metering_label_id': [label_id],
                'direction': [direction],
                'excluded': [excluded]}
        )
        for db_metering_rule in db_metering_rules:
            MeteringPlugin.verify_rule_overlap(
                db_metering_rule, metering_label_rule, "remote_ip_prefix")

    @staticmethod
    def verify_rule_overlap(db_metering_rule, metering_label_rule,
                            attribute_name):
        if db_metering_rule.get(
                attribute_name) and metering_label_rule.get(attribute_name):
            remote_ip_prefix = metering_label_rule[attribute_name]
            cidr = [db_metering_rule.get(attribute_name)]
            new_cidr_ipset = netaddr.IPSet([remote_ip_prefix])

            if netaddr.IPSet(cidr) & new_cidr_ipset:
                LOG.warning("The metering rule [%s] overlaps with"
                            " previously created rule [%s]. It is not an"
                            " expected use case, and people should use"
                            " it wisely.", metering_label_rule,
                            db_metering_rule)
                raise metering_exc.MeteringLabelRuleOverlaps(
                    remote_ip_prefix=remote_ip_prefix)

    def delete_metering_label_rule(self, context, rule_id):
        rule = super(MeteringPlugin, self).delete_metering_label_rule(
            context, rule_id)

        data = self.get_sync_data_for_rule(context, rule)
        self.meter_rpc.remove_metering_label_rule(context, data)
        return rule
