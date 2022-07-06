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

from neutron_lib.api import converters
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import model_query
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_upgradecheck import common_checks
from oslo_upgradecheck import upgradecheck
from sqlalchemy import and_
from sqlalchemy import exists
from sqlalchemy import func
from sqlalchemy import or_

from neutron._i18n import _
from neutron.cmd.upgrade_checks import base
from neutron.db.extra_dhcp_opt import models as extra_dhcp_opt_models
from neutron.db.models import agent as agent_model
from neutron.db.models import external_net
from neutron.db.models import l3 as l3_models
from neutron.db.models.plugins.ml2 import vlanallocation
from neutron.db.models import segment
from neutron.db import models_v2
from neutron.db.qos import models as qos_models
from neutron.objects import ports as port_obj


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


def get_extra_dhcp_opts():
    """Get extra DHCP options for all ports from Database

    :return: list of ports' extra_dhcp_option names and values
    """
    ctx = context.get_admin_context()
    query = model_query.get_collection_query(
        ctx,
        extra_dhcp_opt_models.ExtraDhcpOpt)
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


def count_vlan_allocations_invalid_segmentation_id():
    ctx = context.get_admin_context()
    query = ctx.session.query(vlanallocation.VlanAllocation)
    query = query.filter(or_(
        vlanallocation.VlanAllocation.vlan_id < constants.MIN_VLAN_TAG,
        vlanallocation.VlanAllocation.vlan_id > constants.MAX_VLAN_TAG))
    return query.count()


def port_mac_addresses():
    ctx = context.get_admin_context()
    return [port[0] for port in
            ctx.session.query(models_v2.Port.mac_address).all()]


def get_duplicate_network_segment_count():
    ctx = context.get_admin_context()
    query = ctx.session.query(segment.NetworkSegment.network_id)
    # for a unique constraint it's always NULL != NULL --> we filter them out
    query = query.filter(segment.NetworkSegment.physical_network.isnot(None))
    query = query.group_by(
        segment.NetworkSegment.network_id,
        segment.NetworkSegment.network_type,
        segment.NetworkSegment.physical_network
    )
    query = query.having(func.count() > 1)
    return query.count()


def port_binding_profiles():
    ctx = context.get_admin_context()
    return [port_binding.profile
            for port_binding in port_obj.PortBinding.get_objects(ctx)]


def get_external_networks_with_qos_policies():
    ctx = context.get_admin_context()
    query = ctx.session.query(external_net.ExternalNetwork.network_id)
    query = query.filter(external_net.ExternalNetwork.network_id ==
                         qos_models.QosNetworkPolicyBinding.network_id)
    return [network[0] for network in query.all()]


def get_fip_per_network_without_qos_policies(network_id):
    ctx = context.get_admin_context()
    query = ctx.session.query(l3_models.FloatingIP)
    query = query.filter(and_(
        ~exists().where(qos_models.QosFIPPolicyBinding.fip_id ==
                        l3_models.FloatingIP.id),
        l3_models.FloatingIP.floating_network_id == network_id))
    return query.count()


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
             self.nic_switch_agent_min_kernel_check),
            (_("VLAN allocations valid segmentation ID check"),
             self.vlan_allocations_segid_check),
            (_('Policy File JSON to YAML Migration'),
             (common_checks.check_policy_json, {'conf': cfg.CONF})),
            (_('Port MAC address sanity check'),
             self.port_mac_address_sanity),
            (_('NetworkSegments unique constraint check'),
             self.networksegments_unique_constraint_check),
            (_('Port Binding profile sanity check'),
             self.port_binding_profile_sanity),
            (_('Floating IP inherits the QoS policy from the external '
               'network'),
             self.floatingip_inherit_qos_from_network),
            (_('Port extra DHCP options check'),
             self.extra_dhcp_options_check),
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
        # Background: Issue with old kernel is apparent in CentOS 7 and older.
        # U release is the first release that moves from CentOS-7 to CentOS-8,
        # this was added as a "heads-up" for operators to make sure min kernel
        # requirement is fulfilled.
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

    @staticmethod
    def vlan_allocations_segid_check(checker):
        """Checks that "ml2_vlan_allocations.vlan_id" has a valid value

        Database register column "ml2_vlan_allocations.vlan_id" must be between
        1 and 4094.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for VLAN "
                  "allocations with invalid segmentation IDs can't be done."))

        count = count_vlan_allocations_invalid_segmentation_id()
        if count:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("There are %(count)s registers in 'ml2_vlan_allocations' "
                  "table with an invalid segmentation ID. 'vlan_id' must be "
                  "between %(min_vlan)s and %(max_vlan)s") %
                {'count': count, 'min_vlan': constants.MIN_VLAN_TAG,
                 'max_vlan': constants.MAX_VLAN_TAG})

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _("All 'ml2_vlan_allocations' registers have a valid "
              "segmentation ID."))

    @staticmethod
    def port_mac_address_sanity(checker):
        """Checks the MAC address sanity of each port in the BD

        All MAC addresses should be stored in the format xx:xx:xx:xx:xx:xx.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for port MAC "
                  "sanity can't be done."))

        for mac in port_mac_addresses():
            if mac != converters.convert_to_sanitized_mac_address(mac):
                return upgradecheck.Result(
                    upgradecheck.Code.WARNING,
                    _("There are port MAC addresses not correctly formatted "
                      "in the database. The script "
                      "neutron-sanitize-port-mac-addresses should be "
                      "executed."))

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _("All port MAC addresses are correctly formatted in the "
              "database."))

    @staticmethod
    def networksegments_unique_constraint_check(checker):
        """Checks that there are no duplicate networksegments

        No two networksegments should never share the same network_id,
        network_type and physical_network. Two NULL values are not regarded
        as equal for a unique constraint, so networksegments with NULL as
        physical_network are ignored by this check.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for port MAC "
                  "sanity can't be done."))

        count = get_duplicate_network_segment_count()
        if count:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("There are %d instances of networksegments sharing the same "
                  "combination of network_id, network_type and "
                  "physical_network.") % count)

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _("No networksegments sharing the same network_id, network_type "
              "and physical_network found."))

    @staticmethod
    def port_binding_profile_sanity(checker):
        """Checks that "ml2_port_bindings.profile" uses the new format

        All allocation information should be stored in the following format:
        {'allocation': {'<group_uuid>': '<rp_uuid>'}}.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for "
                  "ml2_port_bindings.profile sanity can't be done."))

        for profile in port_binding_profiles():
            allocation = profile.get('allocation')
            if (allocation and not isinstance(allocation, dict)):
                return upgradecheck.Result(
                    upgradecheck.Code.FAILURE,
                    _("ml2_port_bindings.profile rows are not correctly "
                      "formatted in the database. The script "
                      "neutron-sanitize-port-binding-profile-allocation "
                      "should be executed"))

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _("All ml2_port_bindings.profile rows are correctly formatted in "
              "the database."))

    @staticmethod
    def floatingip_inherit_qos_from_network(checker):
        """Check if a floating IP network has a QoS policy

        Since LP#1950454, the floating IPs inherit the QoS policy from the
        external network. This check emits a warning message in case of having
        any external network with a QoS policy associated and at least one
        bound floating IPs with no QoS policy.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for "
                  "floating IP network QoS inheritance can't be done."))

        network_ids = []
        for network_id in get_external_networks_with_qos_policies():
            if get_fip_per_network_without_qos_policies(network_id):
                network_ids.append(network_id)

        if network_ids:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _('The following external networks have a QoS policy '
                  'associated and at least one floating IP without QoS: %s. '
                  'Since LP#1950454, the floating IPs will inherit the QoS '
                  'policy from the external network.') %
                ', '.join(network_ids))

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _('There are no external networks with QoS policies associated '
              'and floating IPs without.'))

    @staticmethod
    def extra_dhcp_options_check(checker):
        """Check newline char in the extra_dhcp_opts

        Since LP#1939733, extra_dhcp_opts names and values shouldn't contain
        newline characters. This check emits a warning message in case of
        having any extra dhcp option defined with newline char in the name or
        value.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for "
                  "extra_dhcp_opts can't be done."))

        ports_with_invalid_options = []
        for extra_dhcp_opt in get_extra_dhcp_opts():
            if (len(extra_dhcp_opt.opt_name.splitlines()) > 1 or
                    len(extra_dhcp_opt.opt_value.splitlines()) > 1):
                ports_with_invalid_options.append(extra_dhcp_opt.port_id)

        if ports_with_invalid_options:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _('The following ports have an extra DHCP options with '
                  'the newline character inside: %s. '
                  'Please update them manually in the Neutron Database, '
                  'otherwise they will be trimmed automatically before '
                  'used in the DHCP service') %
                ', '.join(ports_with_invalid_options))

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _('There are no extra_dhcp_opts with the newline character '
              'in the option name or option value.'))
