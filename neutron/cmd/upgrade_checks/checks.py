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
from neutron_lib.db import api as db_api
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
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2 import config as ml2_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf import service as conf_service
from neutron.db.extra_dhcp_opt import models as extra_dhcp_opt_models
from neutron.db.models import agent as agent_model
from neutron.db.models import external_net
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3ha as l3ha_models
from neutron.db.models.plugins.ml2 import vlanallocation
from neutron.db.models import segment
from neutron.db import models_v2
from neutron.db.qos import models as qos_models
from neutron.objects import ports as port_obj
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker


OVN_ALEMBIC_TABLE_NAME = "ovn_alembic_version"
LAST_NETWORKING_OVN_EXPAND_HEAD = "e55d09277410"
LAST_NETWORKING_OVN_CONTRACT_HEAD = "1d271ead4eb6"

_OVN_CLIENT = None


def get_agents(agt_type):
    """Get agent information from Database

    :param agt_type: agent type, one of constants.AGENT_TYPE_*
    :return: list of database query results
    """
    filters = {'agent_type': [agt_type]}
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = model_query.get_collection_query(ctx,
                                                 agent_model.Agent,
                                                 filters=filters)
        return query.all()


def get_extra_dhcp_opts():
    """Get extra DHCP options for all ports from Database

    :return: list of ports' extra_dhcp_option names and values
    """
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = model_query.get_collection_query(
            ctx, extra_dhcp_opt_models.ExtraDhcpOpt)
        return query.all()


def get_l3_agents():
    return get_agents(constants.AGENT_TYPE_L3)


def get_nic_switch_agents():
    return get_agents(constants.AGENT_TYPE_NIC_SWITCH)


def get_networks():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = model_query.get_collection_query(ctx,
                                                 models_v2.Network)
        return query.all()


def table_exists(table_name):
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        tables = [t[0] for t in ctx.session.execute("SHOW TABLES;")]
        return table_name in tables


def get_ovn_db_revisions():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        return [row[0] for row in ctx.session.execute(
            "SELECT version_num from %s;" % OVN_ALEMBIC_TABLE_NAME)]  # nosec


def count_vlan_allocations_invalid_segmentation_id():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = ctx.session.query(vlanallocation.VlanAllocation)
        query = query.filter(or_(
            vlanallocation.VlanAllocation.vlan_id < constants.MIN_VLAN_TAG,
            vlanallocation.VlanAllocation.vlan_id > constants.MAX_VLAN_TAG))
        return query.count()


def port_mac_addresses():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        return [port[0] for port in
                ctx.session.query(models_v2.Port.mac_address).all()]


def get_duplicate_network_segment_count():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = ctx.session.query(segment.NetworkSegment.network_id)
        # for a unique constraint it's always NULL != NULL --> we filter them
        # out
        query = query.filter(
            segment.NetworkSegment.physical_network.isnot(None))
        query = query.group_by(
            segment.NetworkSegment.network_id,
            segment.NetworkSegment.network_type,
            segment.NetworkSegment.physical_network,
            segment.NetworkSegment.segment_index,
        )
        query = query.having(func.count() > 1)
        return query.count()


def port_binding_profiles():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        return [port_binding.profile
                for port_binding in port_obj.PortBinding.get_objects(ctx)]


def get_external_networks_with_qos_policies():
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = ctx.session.query(external_net.ExternalNetwork.network_id)
        query = query.filter(external_net.ExternalNetwork.network_id ==
                             qos_models.QosNetworkPolicyBinding.network_id)
        return [network[0] for network in query.all()]


def get_fip_per_network_without_qos_policies(network_id):
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = ctx.session.query(l3_models.FloatingIP)
        query = query.filter(and_(
            ~exists().where(qos_models.QosFIPPolicyBinding.fip_id ==
                            l3_models.FloatingIP.id),
            l3_models.FloatingIP.floating_network_id == network_id))
        return query.count()


def get_duplicated_ha_networks_per_project():
    """Return those HA network reg. that have more than 1 entry per project"""
    ctx = context.get_admin_context()
    with db_api.CONTEXT_READER.using(ctx):
        query = ctx.session.query(l3ha_models.L3HARouterNetwork)
        query = query.group_by(l3ha_models.L3HARouterNetwork.project_id)
        query = query.having(func.count() > 1)
        return query.all()


def get_ovn_client():
    global _OVN_CLIENT
    if _OVN_CLIENT is None:
        mech_worker = worker.MaintenanceWorker
        ovn_api = impl_idl_ovn.OvsdbNbOvnIdl.from_worker(mech_worker)
        ovn_sb_api = impl_idl_ovn.OvsdbSbOvnIdl.from_worker(mech_worker)
        _OVN_CLIENT = ovn_client.OVNClient(ovn_api, ovn_sb_api)
    return _OVN_CLIENT


class CoreChecks(base.BaseChecks):

    def __init__(self):
        super().__init__()
        ml2_conf.register_ml2_plugin_opts()
        ovn_conf.register_opts()

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
            (_('Duplicated HA network per project check'),
             self.extra_dhcp_options_check),
            (_('OVN support for BM provisioning over IPv6 check'),
             self.ovn_for_bm_provisioning_over_ipv6_check),
            (_('ML2/OVS IGMP Flood check'),
             self.ml2_ovs_igmp_flood_check),
            (_('Floating IP Port forwarding and OVN L3 plugin configuration'),
             self.ovn_port_forwarding_configuration_check),
        ]

    @staticmethod
    def worker_count_check(checker):

        if cfg.CONF.api_workers and conf_service.get_rpc_workers():
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

    @staticmethod
    def duplicated_ha_network_per_project_check(checker):
        """Check if there are duplicated HA networks per project

        By definition there could be zero or one HA network per project. In
        case of having more than one register associated to any existing
        project (that should never happen), this check will fail.
        """
        if not cfg.CONF.database.connection:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Database connection string is not set. Check for "
                  "extra_dhcp_opts can't be done."))

        ha_networks = get_duplicated_ha_networks_per_project()
        project_ids = {ha_network['project_id'] for ha_network in ha_networks}
        network_ids = {ha_network['network_id'] for ha_network in ha_networks}
        if project_ids:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _('The following projects have duplicated HA networks: '
                  '%(project_ids)s. This is the list of duplicated HA '
                  'networks: %(network_ids)s' %
                  {'project_ids': project_ids, 'network_ids': network_ids}))

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _('There are no duplicated HA networks in the system.'))

    @staticmethod
    def ovn_for_bm_provisioning_over_ipv6_check(checker):
        """Check if OVN version is new enough to handle IPv6 provisioning

        Support for the required DHCPv6 options was recently added in core
        OVN with c5fd51bd154147a567097eaf61fbebc0b5b39e28 in OVN.
        This check function will raise warning if user is using older OVN
        version, withouth this patch and will have
        ``disable_ovn_dhcp_for_baremetal_ports`` option set to False.
        """

        if cfg.CONF.ovn.disable_ovn_dhcp_for_baremetal_ports:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _("Native OVN DHCP is disabed for baremetal ports."))
        try:
            ovn_client = get_ovn_client()
        except RuntimeError:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _("Invalid OVN connection parameters provided."))
        except Exception as err:
            err_msg = "Failed to connect to OVN. Error: %s" % err
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _(err_msg))

        if ovn_client.is_ipxe_over_ipv6_supported:
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _('Version of OVN supports iPXE over IPv6.'))
        else:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _('Version of OVN does not support iPXE over IPv6 but '
                  '``disable_ovn_dhcp_for_baremetal_ports`` is set to '
                  '``False``. In case if provisioning of baremetal nodes '
                  'is required, please make sure that either '
                  '``disable_ovn_dhcp_for_baremetal_ports`` option is set to '
                  '``True`` and Neutron DHCP agent is available or use '
                  'OVN with patch https://github.com/ovn-org/ovn/commit/'
                  'c5fd51bd154147a567097eaf61fbebc0b5b39e28 which added '
                  'support for iPXE over IPv6. It is available in '
                  'OVN >= 23.06.0.'))

    @staticmethod
    def ml2_ovs_igmp_flood_check(checker):
        """Check for IGMP related traffic behavior changes for ML2/OVS

        Since LP#2044272, the default behavior of IGMP related traffic has
        changed for the ML2/OVS driver. This check raises a warning and
        instruct the user how to configure IGMP to keep the same behavior
        as prior to the upgrade.
        """
        # NOTE(lucasagomes): igmp_flood_reports is not checked as part
        # of this function because its default is already True.
        if ('ovn' not in cfg.CONF.ml2.mechanism_drivers and
                cfg.CONF.OVS.igmp_snooping_enable and
                not cfg.CONF.OVS.igmp_flood_unregistered and
                not cfg.CONF.OVS.igmp_flood):
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _('For non-ML2/OVN deployments where ``igmp_snooping_enable`` '
                  'is enabled, the default behavior of IGMP related traffic '
                  'has changed after LP#2044272. To keep the same behavior '
                  'as before please ensure that the configuration options: '
                  '``igmp_flood_unregistered`` and ``igmp_flood`` are also '
                  'enabled in the [OVS] section of the configuration file.'))

        return upgradecheck.Result(
            upgradecheck.Code.SUCCESS,
            _('IGMP related traffic configuration is not affected.'))

    @staticmethod
    def ovn_port_forwarding_configuration_check(checker):
        ovn_l3_plugin_names = [
            'ovn-router',
            'neutron.services.ovn_l3.plugin.OVNL3RouterPlugin']
        if not any(plugin in ovn_l3_plugin_names
                   for plugin in cfg.CONF.service_plugins):
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS, _('No OVN L3 plugin enabled.'))

        ml2_conf.register_ml2_plugin_opts()
        ovn_conf.register_opts()
        try:
            ovn_utils.validate_port_forwarding_configuration()
            return upgradecheck.Result(
                upgradecheck.Code.SUCCESS,
                _('OVN L3 plugin and Port Forwarding configuration are fine.'))
        except ovn_exc.InvalidPortForwardingConfiguration:
            return upgradecheck.Result(
                upgradecheck.Code.WARNING,
                _('Neutron configuration is invalid. Port forwardings '
                  'can not be used with ML2/OVN backend, distributed '
                  'floating IPs and provider network type(s) used as '
                  'tenant networks.'))
