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
from neutron.db import models_v2


OVN_ALEMBIC_TABLE_NAME = "ovn_alembic_version"
LAST_NETWORKING_OVN_EXPAND_HEAD = "e55d09277410"
LAST_NETWORKING_OVN_CONTRACT_HEAD = "1d271ead4eb6"


def get_agents(agt_type):
    """Get agent information from Database

    :param agt_type: agent type, one of constants.AGENT_TYPE_*
    :return: list of database query results
    """
    filters = {'agent_type': [agt_type]}
    ctx = context.get_admin_context()
    query = model_query.get_collection_query(ctx,
                                             agent_model.Agent,
                                             filters=filters)
    return query.all()


def get_l3_agents():
    return get_agents(constants.AGENT_TYPE_L3)


def get_nic_switch_agents():
    return get_agents(constants.AGENT_TYPE_NIC_SWITCH)


def get_networks():
    ctx = context.get_admin_context()
    query = model_query.get_collection_query(ctx,
                                             models_v2.Network)
    return query.all()


def table_exists(table_name):
    ctx = context.get_admin_context()
    tables = [t[0] for t in ctx.session.execute("SHOW TABLES;")]
    return table_name in tables


def get_ovn_db_revisions():
    ctx = context.get_admin_context()
    return [row[0] for row in ctx.session.execute(
        "SELECT version_num from %s;" % OVN_ALEMBIC_TABLE_NAME)]  # nosec


class CoreChecks(base.BaseChecks):

    def get_checks(self):
        return [
            (_("Gateway external network"),
             self.gateway_external_network_check),
            (_("External network bridge"),
             self.external_network_bridge_check),
            (_("Worker counts configured"), self.worker_count_check),
            (_("Networking-ovn database revision"),
             self.ovn_db_revision_check),
            (_("NIC Switch agent check kernel"),
             self.nic_switch_agent_min_kernel_check)
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

    @staticmethod
    def gateway_external_network_check(checker):
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check of usage of "
                  "'gateway_external_network_id' config option in L3 agents "
                  "can't be done"))

        agents_with_gateway_external_net = []
        for agent in get_l3_agents():
            config_string = agent.get('configurations')
            if not config_string:
                continue
            config = jsonutils.loads(config_string)
            if config.get("gateway_external_network_id"):
                agents_with_gateway_external_net.append(agent.get("host"))

        if agents_with_gateway_external_net:
            agents_list = ", ".join(agents_with_gateway_external_net)
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("L3 agents on hosts %s are still using "
                  "'gateway_external_network_id' config option to configure "
                  "external network used as gateway for routers. "
                  "This option is now removed and routers on those hosts can "
                  "use multiple external networks as gateways.") % agents_list)
        else:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _("L3 agents can use multiple networks as external gateways."))

    @staticmethod
    def network_mtu_check(checker):
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check of 'mtu' in "
                  "networks can't be done"))

        networks_with_empty_mtu_attr = []
        for network in get_networks():
            mtu = network.get('mtu', None)
            if not mtu:
                networks_with_empty_mtu_attr.append(network.get("id"))

        if networks_with_empty_mtu_attr:
            networks_list = ", ".join(networks_with_empty_mtu_attr)
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("The 'mtu' attribute of networks %s are not set "
                  "This attribute can't be null now.") % networks_list)
        else:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _("The 'mtu' attribute of all networks are set."))

    @staticmethod
    def ovn_db_revision_check(checker):
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check of "
                  "networking-ovn database revision can't be done."))
        if not table_exists(OVN_ALEMBIC_TABLE_NAME):
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _("Networking-ovn alembic version table don't exists in "
                  "the database yet."))
        revisions = get_ovn_db_revisions()
        if (LAST_NETWORKING_OVN_EXPAND_HEAD not in revisions or
                LAST_NETWORKING_OVN_CONTRACT_HEAD not in revisions):
            return upgradecheck.Result(
                upgradecheck.Code.FAILURE,
                _("Networking-ovn database tables are not up to date. "
                  "Please firts update networking-ovn to the latest version "
                  "from Train release."))
        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _("Networking-ovn database tables are up to date."))

    @staticmethod
    def nic_switch_agent_min_kernel_check(checker):
        # TODO(adrianc): This was introduced in U release, consider removing
        # in 1-2 cycles.
        # Background: Issue with old kernel is appernet in CentOS 7 and older.
        # U release is the first release that moves from CentOS-7 to CentOS-8,
        # this was added as a "heads-up" for operators to make sure min kernel
        # requirement is fullfiled.
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. "
                  "Check for NIC Switch agent can't be done."))

        agents = get_nic_switch_agents()
        if len(agents):
            hosts = ','.join([agent.get("host") for agent in agents])
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("NIC Switch agents detected on hosts %s, please ensure the "
                  "hosts run with a kernel version 3.13 or newer.") % hosts)
        else:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _("No NIC Switch agents detected."))
