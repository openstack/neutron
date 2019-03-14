# Copyright 2018 Red Hat Inc.
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

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import model_query
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_upgradecheck import upgradecheck

from neutron._i18n import _
from neutron.cmd.upgrade_checks import base
from neutron.db.models import agent as agent_model


def get_l3_agents():
    filters = {'agent_type': [constants.AGENT_TYPE_L3]}
    ctx = context.get_admin_context()
    query = model_query.get_collection_query(ctx,
                                             agent_model.Agent,
                                             filters=filters)
    return query.all()


class CoreChecks(base.BaseChecks):

    def get_checks(self):
        return [
            (_("External network bridge"),
             self.external_network_bridge_check),
            (_("Worker counts configured"), self.worker_count_check)
        ]

    @staticmethod
    def worker_count_check(checker):

        if cfg.CONF.api_workers and cfg.CONF.rpc_workers:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS, _("Number of workers already "
                                             "defined in config"))
        else:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("The default number of workers "
                  "has changed. Please see release notes for the new values, "
                  "but it is strongly encouraged for deployers to manually "
                  "set the values for api_workers and rpc_workers."))

    @staticmethod
    def external_network_bridge_check(checker):
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check of usage of "
                  "'external_network_bridge' config option in L3 agents "
                  "can't be done"))

        agents_with_external_bridge = []
        for agent in get_l3_agents():
            config_string = agent.get('configurations')
            if not config_string:
                continue
            config = jsonutils.loads(config_string)
            if config.get("external_network_bridge"):
                agents_with_external_bridge.append(agent.get("host"))

        if agents_with_external_bridge:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("L3 agents on hosts %s are still using "
                  "'external_network_bridge' config option to provide "
                  "gateway connectivity. This option is now removed. "
                  "Migration of routers from those L3 agents will be "
                  "required to connect them to external network through "
                  "integration bridge.") % agents_with_external_bridge)
        else:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _("L3 agents are using integration bridge to connect external "
                  "gateways"))
