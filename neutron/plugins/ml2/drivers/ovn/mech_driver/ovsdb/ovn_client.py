# Copyright 2019 Red Hat, Inc.
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

import collections
import copy
import datetime
import functools

import netaddr

from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import l3_ext_gw_multihoming
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import qinq as qinq_apidef
from neutron_lib.api.definitions import segment as segment_def
from neutron_lib import constants as const
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from neutron_lib.services.logapi import constants as log_const
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.services.trunk import constants as trunk_const
from neutron_lib.utils import helpers
from neutron_lib.utils import net as n_net
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils
from oslo_utils import timeutils
from oslo_utils import versionutils
from ovsdbapp.backend.ovs_idl import idlutils
import tenacity

from neutron._i18n import _
from neutron.common import _constants as n_const
from neutron.common.ovn import acl as ovn_acl
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as common_utils
from neutron.conf.agent import ovs_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf.plugins.ml2.drivers.ovn.ovn_conf \
    import is_ovn_router_indirect_snat_enabled as is_nested_snat
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.db import segments_db
from neutron.objects import router
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import placement as placement_extension
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions \
    import qos as qos_extension


LOG = log.getLogger(__name__)


def _has_separate_snat_per_subnet(router):
    return utils.is_snat_enabled(router) and not is_nested_snat()


OvnPortInfo = collections.namedtuple(
    "OvnPortInfo",
    [
        "type",
        "options",
        "addresses",
        "port_security",
        "parent_name",
        "tag",
        "dhcpv4_options",
        "dhcpv6_options",
        "cidrs",
        "device_owner",
        "security_group_ids",
        "address4_scope_id",
        "address6_scope_id",
        "vnic_type",
        "capabilities",
        "mtu",
    ],
)


GW_INFO = collections.namedtuple('GW_INFO', ['network_id', 'subnet_id',
                                             'router_ip', 'gateway_ip',
                                             'ip_version', 'ip_prefix'])


class OVNClient:

    def __init__(self, nb_idl, sb_idl):
        self._nb_idl = nb_idl
        self._sb_idl = sb_idl

        self._plugin_property = None
        self._l3_plugin_property = None
        self._is_mcast_flood_broken = None
        self._is_ipxe_over_ipv6_supported = None

        # TODO(ralonsoh): handle the OVN client extensions with an ext. manager
        self._qos_driver = qos_extension.OVNClientQosExtension(driver=self)
        self.placement_extension = (
            placement_extension.OVNClientPlacementExtension(self))

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    @property
    def _l3_plugin(self):
        if self._l3_plugin_property is None:
            self._l3_plugin_property = directory.get_plugin(
                plugin_constants.L3)
        return self._l3_plugin_property

    def _transaction(self, commands, txn=None):
        """Create a new transaction or add the commands to an existing one."""
        if txn is None:
            with self._nb_idl.transaction(check_error=True) as new_txn:
                for cmd in commands:
                    new_txn.add(cmd)
        else:
            for cmd in commands:
                txn.add(cmd)

    def _get_allowed_addresses_from_port(self, port):
        if not port.get(psec.PORTSECURITY):
            return [], []

        if utils.is_lsp_trusted(port):
            return [], []

        allowed_addresses = set()
        new_macs = set()
        addresses = port['mac_address']
        for ip in port.get('fixed_ips', []):
            addresses += ' ' + ip['ip_address']

        for allowed_address in port.get('allowed_address_pairs', []):
            # If allowed address pair has same mac as the port mac,
            # append the allowed ip address to the 'addresses'.
            # Else we will have multiple entries for the same mac in
            # 'Logical_Switch_Port.port_security'.
            if allowed_address['mac_address'] == port['mac_address']:
                addresses += ' ' + allowed_address['ip_address']
            else:
                allowed_addresses.add(allowed_address['mac_address'] + ' ' +
                                      allowed_address['ip_address'])
                new_macs.add(allowed_address['mac_address'])

        allowed_addresses.add(addresses)

        return list(allowed_addresses), list(new_macs)

    def _get_subnet_dhcp_options_for_port(self, port, ip_version):
        """Returns the subnet dhcp options for the port.

        Return the first found DHCP options belong for the port.
        """
        subnets = [
            fixed_ip['subnet_id']
            for fixed_ip in port['fixed_ips']
            if netaddr.IPAddress(fixed_ip['ip_address']).version == ip_version]
        get_opts = self._nb_idl.get_subnets_dhcp_options(subnets)
        if get_opts:
            if ip_version == const.IP_VERSION_6:
                # Always try to find a dhcpv6 stateful v6 subnet to return.
                # This ensures port can get one stateful v6 address when port
                # has multiple dhcpv6 stateful and stateless subnets.
                for opts in get_opts:
                    # We are setting ovn_const.DHCPV6_STATELESS_OPT to "true"
                    # in _get_ovn_dhcpv6_opts, so entries in DHCP_Options table
                    # should have unicode type 'true' if they were defined as
                    # dhcpv6 stateless.
                    if opts['options'].get(
                            ovn_const.DHCPV6_STATELESS_OPT) != 'true':
                        return opts
            return get_opts[0]

    def _merge_map_dhcp_option(self, opt, port_opts, subnet_opts):
        """Merge a port and subnet map DHCP option.

        If a DHCP option exists in both port and subnet, the port
        should inherit the values from the subnet.
        """
        port_opt = port_opts[opt]
        subnet_opt = subnet_opts.get(opt)
        if not subnet_opt:
            return port_opt
        return f'{{{subnet_opt[1:-1]}, {port_opt[1:-1]}}}'

    def _get_port_dhcp_options(self, port, ip_version):
        """Return dhcp options for port.

        In case the port is dhcp disabled, or IP addresses it has belong
        to dhcp disabled subnets, returns None.
        Otherwise, returns a dict:
         - with content from a existing DHCP_Options row for subnet, if the
           port has no extra dhcp options.
         - with only one item ('cmd', AddDHCPOptionsCommand(..)), if the port
           has extra dhcp options. The command should be processed in the same
           transaction with port creating or updating command to avoid orphan
           row issue happen.
        """
        lsp_dhcp_disabled, lsp_dhcp_opts = utils.get_lsp_dhcp_opts(
            port, ip_version)

        if lsp_dhcp_disabled:
            return

        subnet_dhcp_options = self._get_subnet_dhcp_options_for_port(
            port, ip_version)

        if not subnet_dhcp_options:
            # NOTE(lizk): It's possible for Neutron to configure a port with IP
            # address belongs to subnet disabled dhcp. And no DHCP_Options row
            # will be inserted for such a subnet. So in that case, the subnet
            # dhcp options here will be None.
            return

        if not lsp_dhcp_opts:
            return subnet_dhcp_options

        # Check for map DHCP options
        for opt in ovn_const.OVN_MAP_TYPE_DHCP_OPTS:
            if opt in lsp_dhcp_opts:
                lsp_dhcp_opts[opt] = self._merge_map_dhcp_option(
                    opt, lsp_dhcp_opts, subnet_dhcp_options['options'])

        # This port has extra DHCP options defined, so we will create a new
        # row in DHCP_Options table for it.
        subnet_dhcp_options['options'].update(lsp_dhcp_opts)
        subnet_dhcp_options['external_ids'].update(
            {'port_id': port['id']})
        subnet_id = subnet_dhcp_options['external_ids']['subnet_id']
        add_dhcp_opts_cmd = self._nb_idl.add_dhcp_options(
            subnet_id, port_id=port['id'],
            cidr=subnet_dhcp_options['cidr'],
            options=subnet_dhcp_options['options'],
            external_ids=subnet_dhcp_options['external_ids'])
        return {'cmd': add_dhcp_opts_cmd}

    @tenacity.retry(retry=tenacity.retry_if_exception_type(RuntimeError),
                    wait=tenacity.wait_random(min=2, max=3),
                    stop=tenacity.stop_after_attempt(3),
                    reraise=True)
    def _wait_for_port_bindings_host(self, context, port_id):
        db_port = ml2_db.get_port(context, port_id)
        # This is already checked previously but, just to stay on
        # the safe side in case the port is deleted mid-operation
        if not db_port:
            raise RuntimeError(
                _('No port found with ID %s') % port_id)

        if not db_port.port_bindings:
            raise RuntimeError(
                _('No port bindings information found for  '
                  'port %s') % port_id)

        if not db_port.port_bindings[0].host:
            raise RuntimeError(
                _('No hosting information found for port %s') % port_id)

        return db_port

    def update_lsp_host_info(self, context, db_port, up=True):
        """Update the binding hosting information for the LSP.

        Update the binding hosting information in the Logical_Switch_Port
        external_ids column. See LP #2020058 for more information.

        :param context: Neutron API context.
        :param db_port: The Neutron port.
        :param up: If True add the host information, if False remove it.
                   Defaults to True.
        """
        cmd = []
        if db_port.device_owner == trunk_const.TRUNK_SUBPORT_OWNER:
            # NOTE(ralonsoh): OVN subports don't have host ID information.
            return

        port_up = self._nb_idl.lsp_get_up(db_port.id).execute(
            check_error=True)
        if up:
            if not port_up:
                LOG.warning('Logical_Switch_Port %s host information not '
                            'updated, the port state is down')
                return

            if not db_port.port_bindings:
                return

            if not db_port.port_bindings[0].host:
                # NOTE(lucasgomes): There might be a sync issue between
                # the moment that this port was fetched from the database
                # and the hosting information being set, retry a few times
                try:
                    db_port = self._wait_for_port_bindings_host(
                        context, db_port.id)
                except RuntimeError as e:
                    LOG.warning(e)
                    return

            host = db_port.port_bindings[0].host
            ext_ids = ('external_ids',
                       {ovn_const.OVN_HOST_ID_EXT_ID_KEY: host})
            cmd.append(
                self._nb_idl.db_set(
                    'Logical_Switch_Port', db_port.id, ext_ids))
        else:
            if port_up:
                LOG.warning('Logical_Switch_Port %s host information not '
                            'removed, the port state is up')
                return

            cmd.append(
                self._nb_idl.db_remove(
                    'Logical_Switch_Port', db_port.id, 'external_ids',
                    ovn_const.OVN_HOST_ID_EXT_ID_KEY, if_exists=True))

        self._transaction(cmd)

    # TODO(lucasagomes): Remove this method and the logic around the broken
    # mcast_flood_reports configuration option on any other port that is not
    # type "localnet" when the fixed version of OVN becomes the norm.
    # The commit in core OVN fixing this issue is the
    # https://github.com/ovn-org/ovn/commit/6aeeccdf272bc60630581e46aa42d97f4f56d4fa
    @property
    def is_mcast_flood_broken(self):
        if self._is_mcast_flood_broken is None:
            schema_version = self._nb_idl.get_schema_version()
            self._is_mcast_flood_broken = (
                versionutils.convert_version_to_tuple(schema_version) <
                (6, 3, 0))
        return self._is_mcast_flood_broken

    # TODO(slaweq): Remove this method when min supported OVN version will be
    # >= v23.06.0 which is the one which have support for IPv6 iPXE booting
    # added:
    # https://github.com/ovn-org/ovn/commit/c5fd51bd154147a567097eaf61fbebc0b5b39e28
    @property
    def is_ipxe_over_ipv6_supported(self):
        if self._is_ipxe_over_ipv6_supported is None:
            schema_version = self._nb_idl.get_schema_version()
            self._is_ipxe_over_ipv6_supported = (
                versionutils.convert_version_to_tuple(schema_version) >=
                (7, 0, 4))
        return self._is_ipxe_over_ipv6_supported

    def _get_port_options(self, context, port):
        admin_context = context.elevated()
        bp_info = utils.validate_and_get_data_from_binding_profile(port)
        vtep_physical_switch = bp_info.bp_param.get('vtep-physical-switch')

        port_type = ''
        cidrs = ''
        address4_scope_id = ""
        address6_scope_id = ""
        dhcpv4_options = self._get_port_dhcp_options(port, const.IP_VERSION_4)
        dhcpv6_options = self._get_port_dhcp_options(port, const.IP_VERSION_6)
        device_owner = port.get('device_owner', '')
        mtu = ''
        if vtep_physical_switch:
            vtep_logical_switch = bp_info.bp_param.get('vtep-logical-switch')
            port_type = 'vtep'
            options = {'vtep-physical-switch': vtep_physical_switch,
                       'vtep-logical-switch': vtep_logical_switch}
            addresses = [ovn_const.UNKNOWN_ADDR]
            parent_name = []
            tag = []
            port_security = []
        else:
            options = {}
            parent_name = bp_info.bp_param.get('parent_name', [])
            tag = bp_info.bp_param.get('tag', [])
            address = port['mac_address']

            port_fixed_ips = port.get('fixed_ips', [])
            subnet_ids = [
                ip['subnet_id']
                for ip in port_fixed_ips
                if 'subnet_id' in ip
            ]
            subnets = self._plugin.get_subnets(admin_context,
                                               filters={'id': subnet_ids})
            subnets_by_id = {subnet['id']: subnet for subnet in subnets}
            address4_scope_id, address6_scope_id = (
                utils.get_subnets_address_scopes(admin_context, subnets_by_id,
                                                 port_fixed_ips,
                                                 self._plugin))
            p_type, virtual_ip, virtual_parents = (
                utils.get_port_type_virtual_and_parents(
                    subnets_by_id, port_fixed_ips, port['network_id'],
                    port['id'], self._nb_idl))
            if p_type:
                port_type = ovn_const.LSP_TYPE_VIRTUAL
                options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY] = virtual_ip
                options[ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY] = (
                    virtual_parents)
            if subnets_by_id:
                for ip in port_fixed_ips:
                    ip_addr = ip['ip_address']
                    address += ' ' + ip_addr

                    subnet = subnets_by_id.get(ip['subnet_id'])
                    if not subnet:
                        LOG.debug('Subnet not found for ip address %s',
                                  ip_addr)
                        continue

                    cidrs += ' {}/{}'.format(ip['ip_address'],
                                             subnet['cidr'].split('/')[1])

            # Metadata or OVN LB HM port.
            if (utils.is_ovn_metadata_port(port) or
                    utils.is_ovn_lb_hm_port(port)):
                port_type = ovn_const.LSP_TYPE_LOCALPORT

            if utils.is_port_external(port):
                port_type = ovn_const.LSP_TYPE_EXTERNAL

            addresses = []
            port_security, new_macs = (
                self._get_allowed_addresses_from_port(port))
            is_vpn_gw_port = device_owner == n_const.DEVICE_OWNER_VPN_ROUTER_GW
            # TODO(egarciar): OVN supports MAC learning from v21.03. This
            # if-else block is stated so as to keep compatibility with older
            # OVN versions and should be removed in the future.
            if self._sb_idl.is_table_present('FDB'):
                if (port_security or port_type or dhcpv4_options or
                        dhcpv6_options or is_vpn_gw_port):
                    addresses.append(address)
                    addresses.extend(new_macs)
            else:
                addresses = [address]
                addresses.extend(new_macs)

            if not port_security and not port_type:
                # Port security is disabled for this port.
                # So this port can send traffic with any mac address.
                # OVN allows any mac address from a port if "unknown"
                # is added to the Logical_Switch_Port.addresses column.
                # So add it.
                addresses.append(ovn_const.UNKNOWN_ADDR)

        # HA Chassis Group will bind the port to the highest
        # priority Chassis
        if port_type != ovn_const.LSP_TYPE_EXTERNAL:
            if (bp_info.vnic_type == portbindings.VNIC_REMOTE_MANAGED and
                    ovn_const.VIF_DETAILS_PF_MAC_ADDRESS in bp_info.bp_param):
                port_net = self._plugin.get_network(admin_context,
                                                    port['network_id'])
                mtu = str(port_net['mtu'])
                options.update({
                    ovn_const.LSP_OPTIONS_VIF_PLUG_TYPE_KEY: 'representor',
                    ovn_const.LSP_OPTIONS_VIF_PLUG_MTU_REQUEST_KEY: mtu,
                    ovn_const.LSP_OPTIONS_VIF_PLUG_REPRESENTOR_PF_MAC_KEY: (
                        bp_info.bp_param.get(
                            ovn_const.VIF_DETAILS_PF_MAC_ADDRESS)),
                    ovn_const.LSP_OPTIONS_VIF_PLUG_REPRESENTOR_VF_NUM_KEY: str(
                        bp_info.bp_param.get(ovn_const.VIF_DETAILS_VF_NUM))})

            if port_type != ovn_const.LSP_TYPE_VIRTUAL:
                # Virtual ports can not be bound by using the requested-chassis
                # mechanism, ovn-controller will create the Port_Binding entry
                # when it sees an ARP coming from the VIP
                options = self._configure_requested_chassis_options(
                    options, port)

        if self.is_mcast_flood_broken and port_type not in (
                'vtep', ovn_const.LSP_TYPE_LOCALPORT, 'router'):
            options.update({ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true'})
        sg_ids = ' '.join(utils.get_lsp_security_groups(port))

        lsp_options_qos = self._qos_driver.get_lsp_options_qos(port['id'])
        options.update(lsp_options_qos)

        return OvnPortInfo(port_type, options, addresses, port_security,
                           parent_name, tag, dhcpv4_options, dhcpv6_options,
                           cidrs.strip(), device_owner, sg_ids,
                           address4_scope_id, address6_scope_id,
                           bp_info.vnic_type, bp_info.capabilities, mtu
                           )

    def _configure_requested_chassis_options(self, options, port):
        options = copy.deepcopy(options)
        chassis = utils.determine_bind_host(self._sb_idl, port)
        if chassis:
            # If OVN supports multi-chassis port bindings, use it for live
            # migration to asynchronously configure destination port while
            # VM is migrating
            if utils.is_additional_chassis_supported(self._sb_idl):
                mdst = port.get(
                    portbindings.PROFILE, {}).get(ovn_const.MIGRATING_ATTR)
                if mdst:
                    # Let OVN know that the port should be configured on
                    # destination too
                    chassis += ',%s' % mdst
                    # Block traffic on destination host until libvirt sends
                    # a RARP packet from it to inform network about the new
                    # location of the port
                    # TODO(ihrachys) Remove this once OVN properly supports
                    # activation of DPDK ports (bug 2092407)
                    if (port[portbindings.VIF_TYPE] !=
                            portbindings.VIF_TYPE_VHOST_USER):
                        strategy = ovn_conf.get_ovn_lm_activation_strategy()
                        if strategy:
                            options['activation-strategy'] = strategy
            options[ovn_const.LSP_OPTIONS_REQUESTED_CHASSIS_KEY] = chassis
        return options

    def update_port_dhcp_options(self, port_info, txn):
        dhcpv4_options = []
        dhcpv6_options = []
        if not port_info.dhcpv4_options:
            dhcpv4_options = []
        elif 'cmd' in port_info.dhcpv4_options:
            dhcpv4_options = txn.add(port_info.dhcpv4_options['cmd'])
        else:
            dhcpv4_options = [port_info.dhcpv4_options['uuid']]
        if not port_info.dhcpv6_options:
            dhcpv6_options = []
        elif 'cmd' in port_info.dhcpv6_options:
            dhcpv6_options = txn.add(port_info.dhcpv6_options['cmd'])
        else:
            dhcpv6_options = [port_info.dhcpv6_options['uuid']]

        return (dhcpv4_options, dhcpv6_options)

    def get_external_ids_from_port(self, context, port):
        port_info = self._get_port_options(context, port)
        external_ids = {
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY: port['name'],
            ovn_const.OVN_DEVID_EXT_ID_KEY: port['device_id'],
            ovn_const.OVN_PROJID_EXT_ID_KEY: port['project_id'],
            ovn_const.OVN_CIDRS_EXT_ID_KEY: port_info.cidrs,
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: port_info.device_owner,
            ovn_const.OVN_SUBNET_POOL_EXT_ADDR_SCOPE4_KEY:
                port_info.address4_scope_id,
            ovn_const.OVN_SUBNET_POOL_EXT_ADDR_SCOPE6_KEY:
                port_info.address6_scope_id,
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(port['network_id']),
            ovn_const.OVN_SG_IDS_EXT_ID_KEY: port_info.security_group_ids,
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                port, ovn_const.TYPE_PORTS)),
            ovn_const.OVN_PORT_VNIC_TYPE_KEY: port_info.vnic_type,
            ovn_const.OVN_PORT_BP_CAPABILITIES_KEY:
                ';'.join(port_info.capabilities),
            ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY: port_info.mtu,
        }
        return port_info, external_ids

    def create_port(self, context, port):
        if utils.is_lsp_ignored(port):
            return

        port_info, external_ids = self.get_external_ids_from_port(
            context, port)
        lswitch_name = utils.ovn_name(port['network_id'])

        # It's possible to have a network created on one controller and then a
        # port created on a different controller quickly enough that the second
        # controller does not yet see that network in its local cache of the
        # OVN northbound database.  Check if the logical switch is present
        # or not in the idl's local copy of the database before creating
        # the lswitch port. Once we require an ovs version with working
        # persist_uuid support, this can be removed.
        if not utils.ovs_persist_uuid_supported(self._nb_idl):
            self._nb_idl.check_for_row_by_value_and_retry(
                'Logical_Switch', 'name', lswitch_name)

        with self._nb_idl.transaction(check_error=True) as txn:
            dhcpv4_options, dhcpv6_options = self.update_port_dhcp_options(
                port_info, txn=txn)
            # The lport_name *must* be neutron port['id'].  It must match the
            # iface-id set in the Interfaces table of the Open_vSwitch
            # database which nova sets to be the port ID.

            kwargs = {
                'lport_name': port['id'],
                'lswitch_name': lswitch_name,
                'network_id': port['network_id'],
                'addresses': port_info.addresses,
                'external_ids': external_ids,
                'parent_name': port_info.parent_name,
                'tag': port_info.tag,
                'enabled': port.get('admin_state_up'),
                'options': port_info.options,
                'type': port_info.type,
                'port_security': port_info.port_security,
                'dhcpv4_options': dhcpv4_options,
                'dhcpv6_options': dhcpv6_options
            }

            if port_info.type == ovn_const.LSP_TYPE_EXTERNAL:
                kwargs['ha_chassis_group'], _ = (
                    utils.sync_ha_chassis_group_network(
                        context, self._nb_idl, self._sb_idl, port['id'],
                        port['network_id'], txn))

            # NOTE(mjozefcz): Do not set addresses if the port is not
            # bound, has no device_owner and it is OVN LB VIP port.
            # For more details check related bug #1789686.
            if (port.get('name').startswith(ovn_const.LB_VIP_PORT_PREFIX) and
                    not port.get('device_owner') and
                    port.get(portbindings.VIF_TYPE) ==
                    portbindings.VIF_TYPE_UNBOUND):
                kwargs['addresses'] = []

            # Check if the parent port was created with the
            # allowed_address_pairs already set
            allowed_address_pairs = port.get('allowed_address_pairs', [])
            if (allowed_address_pairs and
                    port_info.type != ovn_const.LSP_TYPE_VIRTUAL):
                addrs = [addr['ip_address'] for addr in allowed_address_pairs]
                self._set_unset_virtual_port_type(context, txn, port, addrs)

            port_cmd = txn.add(self._nb_idl.create_lswitch_port(
                **kwargs))

            sg_ids = utils.get_lsp_security_groups(port)
            # If this is not a trusted port and port security is enabled,
            # add it to the default drop Port Group so that all traffic
            # is dropped by default.
            if not utils.is_lsp_trusted(port) and port_info.port_security:
                self._add_port_to_drop_port_group(port_cmd, txn)
            # Just add the port to its Port Group.
            for sg in sg_ids:
                txn.add(self._nb_idl.pg_add_ports(
                    utils.ovn_port_group_name(sg), port_cmd))

            if self.is_dns_required_for_port(port):
                self.add_txns_to_sync_port_dns_records(txn, port)

            self._qos_driver.create_port(context, txn, port, port_cmd)

        db_rev.bump_revision(context, port, ovn_const.TYPE_PORTS)

    def _set_unset_virtual_port_type(self, context, txn, parent_port,
                                     addresses, unset=False):
        cmd = self._nb_idl.set_lswitch_port_to_virtual_type
        if unset:
            cmd = self._nb_idl.unset_lswitch_port_to_virtual_type

        for addr in addresses:
            virt_port = self._plugin.get_ports(context, filters={
                portbindings.VIF_TYPE: portbindings.VIF_TYPE_UNBOUND,
                'network_id': [parent_port['network_id']],
                'fixed_ips': {'ip_address': [addr]}})
            if not virt_port:
                continue
            virt_port = virt_port[0]
            args = {'lport_name': virt_port['id'],
                    'virtual_parent': parent_port['id'],
                    'if_exists': True}
            LOG.debug("Parent port %(virtual_parent)s found for "
                      "virtual port %(lport_name)s", args)
            if not unset:
                args['vip'] = addr
            txn.add(cmd(**args))

    # TODO(lucasagomes): The ``port_object`` parameter was added to
    # keep things backward compatible. Remove it in the Rocky release.
    def update_port(self, context, port, port_object=None):
        if utils.is_lsp_ignored(port):
            return

        admin_context = context.elevated()
        port_info, external_ids = self.get_external_ids_from_port(
            context, port)

        check_rev_cmd = self._nb_idl.check_revision_number(
            port['id'], port, ovn_const.TYPE_PORTS)
        with self._nb_idl.transaction(check_error=True,
                                      revision_mismatch_raise=True) as txn:
            ovn_port = self._nb_idl.lookup('Logical_Switch_Port', port['id'],
                                           default=None)
            if not ovn_port:
                LOG.warning('Logical_Switch_Port deleted concurrently: %s',
                            port['id'])
                return

            txn.add(check_rev_cmd)
            columns_dict = {}
            if utils.is_lsp_router_port(port):
                # It is needed to specify the port type, if not specified
                # the AddLSwitchPortCommand will trigger a change
                # on the northd status column from UP to DOWN, triggering a
                # LogicalSwitchPortUpdateDownEvent, that will most likely
                # cause a revision conflict.
                # https://bugs.launchpad.net/neutron/+bug/1955578
                router_obj = router.Router.get_object(admin_context,
                                                      id=port['device_id'])
                if utils.is_ovn_provider_router(router_obj):
                    columns_dict['type'] = ovn_const.LSP_TYPE_ROUTER
                port_info.options.update(
                    self._nb_idl.get_router_port_options(port['id']))
            else:
                columns_dict['type'] = port_info.type
                columns_dict['addresses'] = port_info.addresses

            dhcpv4_options, dhcpv6_options = self.update_port_dhcp_options(
                port_info, txn=txn)

            if utils.is_ovn_metadata_port(port):
                network = self._plugin.get_network(admin_context,
                                                   port['network_id'])
                subnet_ids = [
                    _ip['subnet_id']
                    for _ip in port['fixed_ips']
                    if 'subnet_id' in _ip
                ]

                for subnet in self._plugin.get_subnets(
                        admin_context, filters={'id': subnet_ids}):
                    if not subnet['enable_dhcp']:
                        continue
                    self._update_subnet_dhcp_options(
                        context, subnet, network, txn)

            # NOTE(mjozefcz): Do not set addresses if the port is not
            # bound, has no device_owner and it is OVN LB VIP port.
            # For more details check related bug #1789686.
            if (port.get('name').startswith(ovn_const.LB_VIP_PORT_PREFIX) and
                    not port.get('device_owner') and
                    port.get(portbindings.VIF_TYPE) ==
                    portbindings.VIF_TYPE_UNBOUND):
                columns_dict['addresses'] = []

            if port_info.type == ovn_const.LSP_TYPE_EXTERNAL:
                columns_dict['ha_chassis_group'], _ = (
                    utils.sync_ha_chassis_group_network(
                        admin_context, self._nb_idl, self._sb_idl, port['id'],
                        port['network_id'], txn))
            else:
                # Clear the ha_chassis_group field
                columns_dict['ha_chassis_group'] = []

            addr_pairs_diff = utils.compute_address_pairs_diff(ovn_port, port)

            if port_info.type != ovn_const.LSP_TYPE_VIRTUAL:
                self._set_unset_virtual_port_type(
                    context, txn, port, addr_pairs_diff.added)
                self._set_unset_virtual_port_type(
                    context, txn, port, addr_pairs_diff.removed,
                    unset=True)

            # Keep key value pairs that were in the original external ids
            # of the ovn port and we did not touch.
            for k, v in ovn_port.external_ids.items():
                external_ids.setdefault(k, v)

            # NOTE(lizk): Fail port updating if port doesn't exist. This
            # prevents any new inserted resources to be orphan, such as port
            # dhcp options or ACL rules for port, e.g. a port was created
            # without extra dhcp options and security group, while updating
            # includes the new attributes setting to port.
            txn.add(self._nb_idl.set_lswitch_port(
                lport_name=port['id'],
                external_ids=external_ids,
                parent_name=port_info.parent_name,
                tag=port_info.tag,
                options=port_info.options,
                enabled=port['admin_state_up'],
                port_security=port_info.port_security,
                dhcpv4_options=dhcpv4_options,
                dhcpv6_options=dhcpv6_options,
                if_exists=False,
                **columns_dict))

            # Determine if security groups or fixed IPs are updated.
            old_sg_ids = set(utils.get_ovn_port_security_groups(ovn_port))
            new_sg_ids = set(utils.get_lsp_security_groups(port))
            detached_sg_ids = old_sg_ids - new_sg_ids
            attached_sg_ids = new_sg_ids - old_sg_ids

            for sg in detached_sg_ids:
                txn.add(self._nb_idl.pg_del_ports(
                    utils.ovn_port_group_name(sg), port['id']))
            for sg in attached_sg_ids:
                txn.add(self._nb_idl.pg_add_ports(
                    utils.ovn_port_group_name(sg), port['id']))
            if (not utils.is_lsp_trusted(port) and
                    utils.is_port_security_enabled(port)):
                self._add_port_to_drop_port_group(port['id'], txn)
            # If the port doesn't belong to any security group and
            # port_security is disabled, or it's a trusted port, then
            # allow all traffic.
            elif ((not new_sg_ids and
                   not utils.is_port_security_enabled(port)) or
                  utils.is_lsp_trusted(port)):
                self._del_port_from_drop_port_group(port['id'], txn)

            self._qos_driver.update_port(context, txn, port, port_object)

            if self.is_dns_required_for_port(port):
                self.add_txns_to_sync_port_dns_records(
                    txn, port, original_port=port_object)
            elif port_object and self.is_dns_required_for_port(port_object):
                # We need to remove the old entries
                self.add_txns_to_remove_port_dns_records(txn, port_object)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(context, port, ovn_const.TYPE_PORTS)

    def _delete_port(self, context, port_id, port_object=None):
        ovn_port = self._nb_idl.lookup('Logical_Switch_Port', port_id)
        ovn_network_name = ovn_port.external_ids.get(
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY)
        network_id = utils.get_neutron_name(ovn_network_name)

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.delete_lswitch_port(
                port_id, ovn_network_name))

            p_object = ({'id': port_id, 'network_id': network_id}
                        if not port_object else port_object)
            self._qos_driver.delete_port(context, txn, p_object)

            if port_object and self.is_dns_required_for_port(port_object):
                self.add_txns_to_remove_port_dns_records(txn, port_object)

            # Check if the port being deleted is a virtual parent
            if ovn_port.type != ovn_const.LSP_TYPE_VIRTUAL:
                ls = self._nb_idl.ls_get(ovn_network_name).execute(
                    check_error=True)
                cmd = self._nb_idl.unset_lswitch_port_to_virtual_type
                for lsp in ls.ports:
                    if lsp.type != ovn_const.LSP_TYPE_VIRTUAL:
                        continue
                    if port_id in lsp.options.get(
                            ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY, ''):
                        txn.add(cmd(lsp.name, port_id, if_exists=True))

    # TODO(lucasagomes): The ``port_object`` parameter was added to
    # keep things backward compatible. Remove it in the Rocky release.
    def delete_port(self, context, port_id, port_object=None):
        try:
            self._delete_port(context, port_id, port_object=port_object)
        except idlutils.RowNotFound:
            # NOTE(dalvarez): At this point the port doesn't exist in the OVN
            # database or, most likely, this worker IDL hasn't been updated
            # yet. See Bug #1960006 for more information. The approach here is
            # to allow at least one maintenance cycle  before we delete the
            # revision number so that the port doesn't stale and eventually
            # gets deleted by the maintenance task.
            rev_row = db_rev.get_revision_row(
                context, port_id, resource_type=ovn_const.TYPE_PORTS)
            time_ = (timeutils.utcnow() - datetime.timedelta(
                seconds=ovn_const.DB_CONSISTENCY_CHECK_INTERVAL + 30))
            if rev_row and rev_row.created_at >= time_:
                return
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to delete port %(port)s. Error: '
                          '%(error)s', {'port': port_id, 'error': e})
        db_rev.delete_revision(context, port_id, ovn_const.TYPE_PORTS)

    def _create_or_update_floatingip(self, context, floatingip, txn=None):
        router_id = floatingip.get('router_id')
        if not router_id:
            return

        # FIPs used for port forwarding have no fixed address
        # configured. Also, OVN handler for port forwarding
        # is delegated to OVNPortForwarding. Nothing further
        # to do here.
        if floatingip['fixed_ip_address'] is None:
            LOG.debug("Skipping NAT for floating ip %(id)s, external ip "
                      "%(fip_ip)s on router %(rtr_id)s: no logical_ip",
                      {'id': floatingip['id'],
                       'fip_ip': floatingip['floating_ip_address'],
                       'rtr_id': router_id})
            return

        commands = []
        admin_context = context.elevated()
        fip_db = self._l3_plugin._get_floatingip(
            admin_context, floatingip['id'])
        port_db = self._plugin.get_port(
            admin_context, fip_db['floating_port_id'])

        gw_lrouter_name = utils.ovn_name(router_id)
        ext_ids = {
            ovn_const.OVN_FIP_EXT_ID_KEY: floatingip['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                floatingip, ovn_const.TYPE_FLOATINGIPS)),
            ovn_const.OVN_FIP_PORT_EXT_ID_KEY: floatingip['port_id'],
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: gw_lrouter_name,
            ovn_const.OVN_FIP_EXT_MAC_KEY: port_db['mac_address'],
            ovn_const.OVN_FIP_NET_ID: floatingip['floating_network_id']}
        stateless_nat = ('true' if ovn_conf.is_stateless_nat_enabled() else
                         'false')
        options = {'stateless': stateless_nat}
        columns = {'type': 'dnat_and_snat',
                   'logical_ip': floatingip['fixed_ip_address'],
                   'external_ip': floatingip['floating_ip_address'],
                   'logical_port': floatingip['port_id'],
                   'external_ids': ext_ids,
                   'options': options,
                   }

        # If OVN supports gateway_port column for NAT rules set gateway port
        # uuid to floating IP without gw port reference - LP#2035281.
        if utils.is_nat_gateway_port_supported(self._nb_idl):
            router_db = self._l3_plugin.get_router(admin_context, router_id)
            gw_port_id = router_db.get('gw_port_id')
            lrp = self._nb_idl.get_lrouter_port(gw_port_id)
            # If LRP is not bound to a chassis, it means that router can be
            # bound instead. In this case we do not want to define
            # gateway_port LP#2083527.
            if lrp.options.get(
                    ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH) == 'true':
                columns['gateway_port'] = lrp.uuid

        if ovn_conf.is_ovn_distributed_floating_ip():
            if self._nb_idl.lsp_get_up(floatingip['port_id']).execute():
                columns['external_mac'] = port_db['mac_address']

        # TODO(mjozefcz): Remove this workaround when OVN LB
        # will support both decentralized FIPs on LB and member.
        lb_member_fip = self._is_lb_member_fip(admin_context, floatingip)
        if (ovn_conf.is_ovn_distributed_floating_ip() and
                lb_member_fip):
            LOG.warning("Port %s is configured as a member "
                        "of one of OVN Load_Balancers and "
                        "Load_Balancer has FIP assigned. "
                        "In order to make traffic work member "
                        "FIP needs to be centralized, even if "
                        "this environment is configured as DVR. "
                        "Removing logical_port and external_mac from "
                        "NAT entry.", floatingip['port_id'])
            columns.pop('logical_port', None)
            columns.pop('external_mac', None)
        commands.append(self._nb_idl.add_nat_rule_in_lrouter(gw_lrouter_name,
                                                             **columns))

        # Get the logical port (of the private network) and set the field
        # external_ids:fip=<FIP>. This will be used by the ovn octavia driver
        # to add the floating ip as vip in the Load_Balancer.vips column.
        private_lsp = self._nb_idl.get_lswitch_port(floatingip['port_id'])

        if private_lsp:
            port_fip = {
                ovn_const.OVN_PORT_FIP_EXT_ID_KEY:
                    floatingip['floating_ip_address']}
            commands.append(
                self._nb_idl.db_set('Logical_Switch_Port', private_lsp.uuid,
                                    ('external_ids', port_fip))
            )
            if not lb_member_fip:
                commands.extend(
                    self._handle_lb_fip_cmds(
                        admin_context, private_lsp,
                        action=ovn_const.FIP_ACTION_ASSOCIATE))
        else:
            LOG.warning("LSP for floatingip %s, has not been found! "
                        "Cannot set FIP on VIP.",
                        floatingip['id'])
        self._transaction(commands, txn=txn)

    def _is_lb_member_fip(self, context, fip):
        port = self._plugin.get_port(
            context, fip['port_id'])
        member_subnet = [ip['subnet_id'] for ip in port['fixed_ips']
                         if ip['ip_address'] == fip['fixed_ip_address']]
        if not member_subnet:
            return False
        member_subnet = member_subnet[0]

        ls = self._nb_idl.lookup(
            'Logical_Switch', utils.ovn_name(port['network_id']))
        for lb in ls.load_balancer:
            for ext_id in lb.external_ids.keys():
                if ext_id.startswith(ovn_const.LB_EXT_IDS_POOL_PREFIX):
                    members = lb.external_ids[ext_id]
                    if not members:
                        continue
                    for member in members.split(','):
                        if ('%s:' % fip['fixed_ip_address'] in member and
                                '_%s' % member_subnet in member):
                            return True
        return False

    def _handle_lb_fip_cmds(self, context, lb_lsp,
                            action=ovn_const.FIP_ACTION_ASSOCIATE):
        if not ovn_conf.is_ovn_distributed_floating_ip():
            return

        lb_lsp_fip_port = lb_lsp.external_ids.get(
            ovn_const.OVN_PORT_NAME_EXT_ID_KEY, '')

        if not lb_lsp_fip_port.startswith(ovn_const.LB_VIP_PORT_PREFIX):
            return

        # This is a FIP on LB VIP.
        # Loop over members and delete FIP external_mac/logical_port enteries.
        # Find all LBs with this LSP as VIP.
        lbs = self._nb_idl.db_find_rows(
            'Load_Balancer',
            ('external_ids', '=', {
                ovn_const.LB_EXT_IDS_VIP_PORT_ID_KEY: lb_lsp.name})
        ).execute(check_error=True)
        all_lswitches = self._nb_idl.db_find_rows(
            'Logical_Switch').execute(check_error=True)
        attached_lbs = {
            lb for item in all_lswitches for lb in item.load_balancer}

        for lb in lbs:
            if lb not in attached_lbs:
                # LB is not linked anywhere.
                continue

            # Find out IP addresses and subnets of configured members.
            for ext_id in lb.external_ids.keys():
                if not ext_id.startswith(ovn_const.LB_EXT_IDS_POOL_PREFIX):
                    continue
                members = lb.external_ids[ext_id]
                if not members:
                    continue
                for member in members.split(','):
                    # NOTE(mjozefcz): Remove this workaround in W release.
                    # Last argument of member info is a subnet_id from from
                    # which member comes from.
                    # member_`id`_`ip`:`port`_`subnet_ip`
                    member_info = member.split('_')
                    if len(member_info) < 4:
                        continue
                    m = {
                        'id': member_info[1],
                        'ip': member_info[2].split(':')[0],
                        'subnet_id': member_info[3],
                    }
                    try:
                        subnet = self._plugin.get_subnet(context,
                                                         m['subnet_id'])
                        m['network_id'] = subnet['network_id']
                    except n_exc.SubnetNotFound:
                        LOG.debug("Cannot find subnet details for "
                                  "OVN LB member %s.", m['id'])
                        continue
                    yield from self._verify_member(context, action, m)

    def _verify_member(self, context, action, member):
        ls = self._nb_idl.lookup(
            'Logical_Switch', utils.ovn_name(member['network_id']))
        for lsp in ls.ports:
            if not lsp.addresses:
                continue
            ips = utils.remove_macs_from_lsp_addresses(lsp.addresses)
            if member['ip'] not in ips:
                continue
            member['lsp'] = lsp
            nats = self._nb_idl.db_find_rows(
                'NAT',
                ('external_ids', '=', {
                    ovn_const.OVN_FIP_PORT_EXT_ID_KEY: lsp.name})
            ).execute(check_error=True)

            for nat in nats:
                if action == ovn_const.FIP_ACTION_ASSOCIATE:
                    # NOTE(mjozefcz): We should delete logical_port and
                    # external_mac entries from member NAT in order to
                    # make traffic work.
                    LOG.warning(
                        "Port %s is configured as a member of one of OVN "
                        "Load_Balancers and Load_Balancer has FIP assigned. "
                        "In order to make traffic work member FIP needs to be "
                        "centralized, even if this environment is configured "
                        "as DVR. Removing logical_port and external_mac from "
                        "NAT entry.", lsp.name)
                    for field_to_clear in ('external_mac', 'logical_port'):
                        yield self._nb_idl.db_clear(
                            'NAT', nat.uuid, field_to_clear)
                else:
                    # NOTE(mjozefcz): The FIP from LB VIP is disassociated now.
                    # We can decentralize member FIPs now.
                    LOG.warning(
                        "Port %s is configured as a member of one of OVN "
                        "Load_Balancers and Load_Balancer has FIP "
                        "disassociated. DVR for this port can be enabled "
                        "back.", lsp.name)
                    yield self._nb_idl.db_set(
                        'NAT', nat.uuid, ('logical_port', lsp.name))
                    port = self._plugin.get_port(context, lsp.name)
                    if port['status'] == const.PORT_STATUS_ACTIVE:
                        yield self._nb_idl.db_set(
                            'NAT', nat.uuid,
                            ('external_mac', port['mac_address']))

    def _delete_floatingip(self, context, fip, lrouter, txn=None):
        commands = [self._nb_idl.delete_nat_rule_in_lrouter(
            lrouter, type='dnat_and_snat',
            logical_ip=fip['logical_ip'],
            external_ip=fip['external_ip'])]
        try:
            port_id = (
                fip['external_ids'].get(ovn_const.OVN_FIP_PORT_EXT_ID_KEY))
            if port_id:
                private_lsp = self._nb_idl.get_lswitch_port(port_id)
                if private_lsp:
                    commands.append(
                        self._nb_idl.db_remove(
                            'Logical_Switch_Port', private_lsp.uuid,
                            'external_ids',
                            (ovn_const.OVN_PORT_FIP_EXT_ID_KEY)))
                    commands.extend(
                        self._handle_lb_fip_cmds(
                            context.elevated(),
                            private_lsp,
                            action=ovn_const.FIP_ACTION_DISASSOCIATE))
        except KeyError:
            LOG.debug("FIP %s doesn't have external_ids.", fip)
        self._transaction(commands, txn=txn)

    def update_floatingip_status(self, context, floatingip):
        # NOTE(lucasagomes): OVN doesn't care about the floating ip
        # status, this method just bumps the revision number
        check_rev_cmd = self._nb_idl.check_revision_number(
            floatingip['id'], floatingip, ovn_const.TYPE_FLOATINGIPS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(
                context, floatingip, ovn_const.TYPE_FLOATINGIPS)

    def create_floatingip(self, context, floatingip):
        try:
            with self._nb_idl.transaction(check_error=True) as txn:
                self._create_or_update_floatingip(context, floatingip, txn=txn)
                self._qos_driver.create_floatingip(context, txn, floatingip)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to create floating ip in gateway '
                          'router. Error: %s', e)

        db_rev.bump_revision(context, floatingip, ovn_const.TYPE_FLOATINGIPS)

        # NOTE(lucasagomes): Revise the expected status
        # of floating ips, setting it to ACTIVE here doesn't
        # see consistent with other drivers (ODL here), see:
        # https://bugs.launchpad.net/networking-ovn/+bug/1657693
        if floatingip.get('router_id'):
            self._l3_plugin.update_floatingip_status(
                context.elevated(), floatingip['id'],
                const.FLOATINGIP_STATUS_ACTIVE)

    def update_floatingip(self, context, floatingip, fip_request=None):
        fip_status = None
        router_id = None
        ovn_fip = self._nb_idl.get_floatingip(floatingip['id'])
        fip_request = fip_request[l3.FLOATINGIP] if fip_request else {}
        qos_update_only = (len(fip_request.keys()) == 1 and
                           qos_consts.QOS_POLICY_ID in fip_request)

        check_rev_cmd = self._nb_idl.check_revision_number(
            floatingip['id'], floatingip, ovn_const.TYPE_FLOATINGIPS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            # If FIP updates the QoS policy only, skip the OVN NAT rules update
            if not qos_update_only:
                if ovn_fip:
                    lrouter = ovn_fip['external_ids'].get(
                        ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY,
                        utils.ovn_name(router_id))
                    self._delete_floatingip(context, ovn_fip, lrouter, txn=txn)
                    fip_status = const.FLOATINGIP_STATUS_DOWN

                if floatingip.get('port_id'):
                    self._create_or_update_floatingip(context, floatingip,
                                                      txn=txn)
                    fip_status = const.FLOATINGIP_STATUS_ACTIVE

            self._qos_driver.update_floatingip(context, txn, floatingip)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(
                context, floatingip, ovn_const.TYPE_FLOATINGIPS)

        if fip_status:
            self._l3_plugin.update_floatingip_status(
                context, floatingip['id'], fip_status)

    def delete_floatingip(self, context, fip_id):
        router_id = None
        ovn_fip = self._nb_idl.get_floatingip(fip_id)

        if ovn_fip:
            lrouter = ovn_fip['external_ids'].get(
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY,
                utils.ovn_name(router_id))
            fip_net_id = ovn_fip['external_ids'].get(ovn_const.OVN_FIP_NET_ID)
            fip_dict = {'floating_network_id': fip_net_id, 'id': fip_id}
            try:
                with self._nb_idl.transaction(check_error=True) as txn:
                    self._delete_floatingip(context, ovn_fip, lrouter, txn=txn)
                    self._qos_driver.delete_floatingip(context, txn, fip_dict)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Unable to delete floating ip in gateway '
                              'router. Error: %s', e)
        db_rev.delete_revision(context, fip_id, ovn_const.TYPE_FLOATINGIPS)

    def disassociate_floatingip(self, context, floatingip, router_id):
        lrouter = utils.ovn_name(router_id)
        try:
            with self._nb_idl.transaction(check_error=True) as txn:
                self._delete_floatingip(context, floatingip, lrouter, txn=txn)
                self._qos_driver.delete_floatingip(context, txn, floatingip)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to disassociate floating ip in gateway '
                          'router. Error: %s', e)

    def _get_gw_info(self, context, port_dict):
        gateways_info = []
        network_id = port_dict.get('network_id')
        subnet_by_id = {
            subnet['id']: subnet
            for subnet in self._plugin.get_subnets_by_network(
                context, network_id)}
        for fixed_ip in port_dict.get('fixed_ips'):
            subnet_id = fixed_ip.get('subnet_id')
            subnet = subnet_by_id.get(subnet_id)
            ip_version = subnet.get('ip_version')
            gateways_info.append(GW_INFO(
                network_id, subnet_id, fixed_ip.get('ip_address'),
                subnet.get('gateway_ip'), ip_version,
                const.IPv4_ANY if ip_version == const.IP_VERSION_4
                else const.IPv6_ANY))
        return gateways_info

    def _delete_router_ext_gw(self, context, router_id, txn):
        admin_context = context.elevated()
        cidrs = self._get_snat_cidrs_for_external_router(admin_context,
                                                         router_id)
        gw_lrouter_name = utils.ovn_name(router_id)
        deleted_ports = []
        for gw_port in self._get_router_gw_ports(admin_context, router_id):
            routes_to_delete = []
            for gw_info in self._get_gw_info(admin_context, gw_port):
                routes_to_delete.append((gw_info.ip_prefix,
                                         gw_info.gateway_ip))

                if gw_info.ip_version != const.IP_VERSION_4:
                    continue
                for cidr in cidrs:
                    txn.add(self._nb_idl.delete_nat_rule_in_lrouter(
                        gw_lrouter_name, type='snat',
                        external_ip=gw_info.router_ip,
                        logical_ip=cidr))

            txn.add(self._nb_idl.delete_static_routes(
                    gw_lrouter_name, routes_to_delete))
            txn.add(self._nb_idl.delete_lrouter_port(
                utils.ovn_lrouter_port_name(gw_port['id']),
                gw_lrouter_name))
            deleted_ports.append(gw_port['id'])
        return deleted_ports

    def _get_nets_and_ipv6_ra_confs_for_router_port(self, context, port):
        port_fixed_ips = port['fixed_ips']
        networks = set()
        ipv6_ra_configs = {}
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')

        for fixed_ip in port_fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            cidr = netaddr.IPNetwork(subnet['cidr'])
            networks.add("{}/{}".format(fixed_ip['ip_address'],
                                        str(cidr.prefixlen)))

            if subnet.get('ipv6_address_mode') and not ipv6_ra_configs:
                ipv6_ra_configs['address_mode'] = (
                    utils.get_ovn_ipv6_address_mode(
                        subnet['ipv6_address_mode']))
                net = self._plugin.get_network(context, subnet['network_id'])
                # If it's a gateway port and connected to a provider
                # network set send_periodic to False, that way we do not
                # leak the RAs generated for the tenant networks via the
                # provider network
                ipv6_ra_configs['send_periodic'] = 'true'
                if is_gw_port and utils.is_external_network(net):
                    ipv6_ra_configs['send_periodic'] = 'false'
                ipv6_ra_configs['mtu'] = str(net['mtu'])

        return list(networks), ipv6_ra_configs

    def _add_router_ext_gw(self, context, router, txn):
        lrouter_name = utils.ovn_name(router['id'])
        router_default_route_ecmp_enabled = router.get(
            'enable_default_route_ecmp', False)
        router_default_route_bfd_enabled = router.get(
            'enable_default_route_bfd', False)

        # 1. Add the external gateway router port.
        admin_context = context.elevated()
        added_ports = []
        for gw_port in self._get_router_gw_ports(admin_context, router['id']):
            port = self._plugin.get_port(admin_context, gw_port['id'])
            self._create_lrouter_port(admin_context, router, port, txn=txn)
            added_ports.append(port)

            # 2. Add default route with nexthop as gateway ip
            if (gw_port['id'] != router.get('gw_port_id') and
                    not router_default_route_ecmp_enabled):
                # The `enable_default_route_ecmp` option is not enabled for
                # the router, only adding routes for the first gw_port.
                continue
            for gw_info in self._get_gw_info(admin_context, gw_port):
                if gw_info.gateway_ip is None:
                    continue
                columns = {'external_ids': {
                    ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                    ovn_const.OVN_SUBNET_EXT_ID_KEY: gw_info.subnet_id,
                    ovn_const.OVN_LRSR_EXT_ID_KEY: 'true'}}
                if router_default_route_bfd_enabled:
                    columns.update({
                        'output_port': utils.ovn_lrouter_port_name(
                            gw_port['id']),
                    })
                txn.add(self._nb_idl.add_static_route(
                    lrouter_name, ip_prefix=gw_info.ip_prefix,
                    nexthop=gw_info.gateway_ip,
                    maintain_bfd=router_default_route_bfd_enabled,
                    **columns))

        # 3. Add necessary snat rule(s) in lrouter if snat is enabled
        if utils.is_snat_enabled(router):
            self.update_nat_rules(context, router['id'], enable_snat=True,
                                  txn=txn)
        return added_ports

    def _check_external_ips_changed(self, context, ovn_snats,
                                    ovn_static_routes, router):
        admin_context = context.elevated()
        ovn_gw_subnets = [
            getattr(route, 'external_ids', {}).get(
                ovn_const.OVN_SUBNET_EXT_ID_KEY) for route in
            ovn_static_routes]

        for gw_port in self._get_router_gw_ports(admin_context, router['id']):
            gw_infos = self._get_gw_info(admin_context, gw_port)
            if not gw_infos:
                # The router is attached to a external network without a subnet
                lrp = self._nb_idl.get_lrouter_port(
                    utils.ovn_lrouter_port_name(gw_port['id']))
                if not lrp:
                    continue
                lrp_ext_ids = getattr(lrp, 'external_ids', {})
                if (ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY in lrp_ext_ids and
                        lrp_ext_ids[ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY] != (
                            utils.ovn_name(gw_port['network_id']))):
                    return True

            for gw_info in gw_infos:
                if ovn_gw_subnets and gw_info.subnet_id not in ovn_gw_subnets:
                    return True
                if gw_info.ip_version == const.IP_VERSION_6:
                    continue
                for snat in ovn_snats:
                    if snat.external_ip != gw_info.router_ip:
                        return True

        router_default_route_bfd = router.get(
            'enable_default_route_bfd',
            False
        )

        for route in ovn_static_routes:
            # If gateway in OVN DB has static routes, the ovn_static_route
            # parameter contains data from
            # `utils.get_lrouter_ext_gw_static_route`, otherwise it will
            # contain a Dict ref `update_router` method.
            route_bfd = getattr(route, 'bfd', [])
            if router_default_route_bfd and not route_bfd:
                return True
            if route_bfd and not router_default_route_bfd:
                return True

        return False

    def update_router_routes(self, context, router_id, add, remove,
                             txn=None):
        if not any([add, remove]):
            return
        lrouter_name = utils.ovn_name(router_id)
        commands = []
        for route in add:
            columns = {'external_ids': {
                ovn_const.OVN_LRSR_EXT_ID_KEY: 'true'}}
            commands.append(
                self._nb_idl.add_static_route(
                    lrouter_name, ip_prefix=route['destination'],
                    nexthop=route['nexthop'], **columns))
        routes_to_delete = [
            (r['destination'], r['nexthop'])
            for r in remove
        ]
        commands.append(
            self._nb_idl.delete_static_routes(lrouter_name,
                                              routes_to_delete)
        )
        self._transaction(commands, txn=txn)

    def _get_router_gw_ports(self, context, router_id):
        # NOTE(fnordahl): an elevated context is required here to ensure we
        # have access to the data.
        return self._plugin.get_ports(context.elevated(), filters={
            'device_owner': [const.DEVICE_OWNER_ROUTER_GW],
            'device_id': [router_id]})

    def _get_router_ports(self, context, router_id):
        # _get_router() will raise a RouterNotFound error if there's no router
        # with the router_id
        router_db = self._l3_plugin._get_router(context, router_id)
        # When the existing deployment is migrated to OVN
        # we may need to consider other port types - DVR_INTERFACE/HA_INTF.
        return [p.port for p in router_db.attached_ports
                if p.port_type in [const.DEVICE_OWNER_ROUTER_INTF,
                                   const.DEVICE_OWNER_DVR_INTERFACE,
                                   const.DEVICE_OWNER_HA_REPLICATED_INT,
                                   const.DEVICE_OWNER_ROUTER_HA_INTF]]

    def _get_v4_network_for_router_port(self, context, port):
        cidr = None
        for fixed_ip in port['fixed_ips']:
            subnet_id = fixed_ip['subnet_id']
            subnet = self._plugin.get_subnet(context, subnet_id)
            if subnet['ip_version'] != const.IP_VERSION_4:
                continue
            cidr = subnet['cidr']
        return cidr

    def _get_v4_network_of_all_router_ports(self, context, router_id):
        networks = []
        for port in self._get_router_ports(context, router_id):
            network = self._get_v4_network_for_router_port(context, port)
            if network:
                networks.append(network)
        return networks

    def _get_snat_cidrs_for_external_router(self, context, router_id):
        if is_nested_snat():
            return [const.IPv4_ANY]
        # nat rule per attached subnet per external ip
        return self._get_v4_network_of_all_router_ports(context, router_id)

    def _gen_router_ext_ids(self, router):
        return {
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                router.get('name', 'no_router_name'),
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                router, ovn_const.TYPE_ROUTERS)),
            ovn_const.OVN_AZ_HINTS_EXT_ID_KEY:
                ','.join(common_utils.get_az_hints(router)),
        }

    def create_router(self, context, router, add_external_gateway=True):
        """Create a logical router."""
        external_ids = self._gen_router_ext_ids(router)
        enabled = router.get('admin_state_up')
        lrouter_name = utils.ovn_name(router['id'])
        added_gw_ports = []
        options = {'always_learn_from_arp_request': 'false',
                   'dynamic_neigh_routers': 'true',
                   ovn_const.LR_OPTIONS_MAC_AGE_LIMIT:
                   ovn_conf.get_ovn_mac_binding_age_threshold()}
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.lr_add(router=lrouter_name, may_exist=True,
                                        external_ids=external_ids,
                                        enabled=enabled, options=options))
            # TODO(lucasagomes): add_external_gateway is being only used
            # by the ovn_db_sync.py script, remove it after the database
            # synchronization work
            if add_external_gateway:
                if router.get(l3_ext_gw_multihoming.EXTERNAL_GATEWAYS):
                    added_gw_ports = self._add_router_ext_gw(
                        context, router, txn)

            self._qos_driver.create_router(context, txn, router)

        for gw_port in added_gw_ports:
            db_rev.bump_revision(context, gw_port,
                                 ovn_const.TYPE_ROUTER_PORTS)
        db_rev.bump_revision(context, router, ovn_const.TYPE_ROUTERS)

    # TODO(lucasagomes): The ``router_object`` parameter was added to
    # keep things backward compatible with old routers created prior to
    # the database sync work. Remove it in the Rocky release.
    def update_router(self, context, new_router, router_object=None):
        """Update a logical router."""
        router_id = new_router['id']
        router_name = utils.ovn_name(router_id)
        ovn_router = self._nb_idl.get_lrouter(router_name)
        # Note that this needs to be retrieved from the request
        gateway_new = new_router.get(l3_ext_gw_multihoming.EXTERNAL_GATEWAYS)
        gateway_old = utils.get_lrouter_ext_gw_static_route(ovn_router)
        added_gw_ports = []
        deleted_gw_port_ids = []

        if router_object:
            gateway_old = gateway_old or router_object.get(
                l3_ext_gw_multihoming.EXTERNAL_GATEWAYS)

        ovn_snats = utils.get_lrouter_snats(ovn_router)
        try:
            check_rev_cmd = self._nb_idl.check_revision_number(
                router_name, new_router, ovn_const.TYPE_ROUTERS)
            with self._nb_idl.transaction(check_error=True) as txn:
                txn.add(check_rev_cmd)
                if gateway_new and not gateway_old:
                    # Route gateway is set
                    added_gw_ports = self._add_router_ext_gw(
                        context, new_router, txn)
                elif gateway_old and not gateway_new:
                    # router gateway is removed
                    txn.add(self._nb_idl.delete_lrouter_ext_gw(router_name))
                    if router_object:
                        deleted_gw_port_ids = self._delete_router_ext_gw(
                            context, router_object['id'], txn)
                elif gateway_new and gateway_old:
                    # Check if external gateway has changed, if yes, delete
                    # the old gateway and add the new gateway
                    ovn_router_ext_gw_lrps = [
                        port
                        for port in getattr(ovn_router, 'ports', [])
                        if strutils.bool_from_string(
                            getattr(port, 'external_ids', {}).get(
                                ovn_const.OVN_ROUTER_IS_EXT_GW, False))
                    ]
                    if (len(gateway_new) != len(ovn_router_ext_gw_lrps) or
                        self._check_external_ips_changed(
                            context, ovn_snats, gateway_old, new_router)):
                        txn.add(self._nb_idl.delete_lrouter_ext_gw(
                            router_name))
                        if router_object:
                            deleted_gw_port_ids = self._delete_router_ext_gw(
                                context, router_object['id'], txn)
                        added_gw_ports = self._add_router_ext_gw(
                            context, new_router, txn)
                    else:
                        # Check if snat has been enabled/disabled and update
                        new_snat_state = utils.is_snat_enabled(new_router)
                        if bool(ovn_snats) != new_snat_state:
                            self.update_nat_rules(
                                context, new_router['id'],
                                enable_snat=new_snat_state, txn=txn)

                update = {'external_ids': self._gen_router_ext_ids(new_router)}
                update['enabled'] = new_router.get('admin_state_up') or False
                txn.add(self._nb_idl.update_lrouter(router_name, **update))

                # Check for route updates
                routes = new_router.get('routes', [])
                old_routes = utils.get_lrouter_non_gw_routes(ovn_router)
                added, removed = helpers.diff_list_of_dict(
                    old_routes, routes)
                self.update_router_routes(
                    context, router_id, added, removed, txn=txn)
                self._qos_driver.update_router(context, txn, new_router)

            if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
                db_rev.bump_revision(context, new_router,
                                     ovn_const.TYPE_ROUTERS)

            for gw_port in added_gw_ports:
                db_rev.bump_revision(context, gw_port,
                                     ovn_const.TYPE_ROUTER_PORTS)

            for gw_port in deleted_gw_port_ids:
                db_rev.delete_revision(context, gw_port,
                                       ovn_const.TYPE_ROUTER_PORTS)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to update router %(router)s. '
                          'Error: %(error)s', {'router': router_id,
                                               'error': e})

    def delete_router(self, context, router_id):
        """Delete a logical router."""
        lrouter_name = utils.ovn_name(router_id)
        with self._nb_idl.transaction(check_error=True) as txn:
            # This will ensure any BFD records are removed
            txn.add(self._nb_idl.delete_lrouter_ext_gw(lrouter_name,
                                                       if_exists=True))
            txn.add(self._nb_idl.lr_del(lrouter_name, if_exists=True))
        db_rev.delete_revision(context, router_id, ovn_const.TYPE_ROUTERS)

    def get_candidates_for_scheduling(self, physnet, cms=None,
                                      chassis_physnets=None,
                                      availability_zone_hints=None):
        """Return chassis for scheduling gateway router.

        Criteria for selecting chassis as candidates
        1) Chassis from cms with proper bridge mappings only (that means these
           gateway chassis with the requested physical network).
        2) Filter the available chassis accordingly to the routers
           availability zone hints (if present)

        If the logical router port belongs to a tunnelled network, there won't
        be any candidate.
        """
        # TODO(lucasagomes): Simplify the logic here, the CMS option has
        # been introduced long ago and by now all gateway chassis should
        # include it. This will match the logic in the is_gateway_chassis()
        # (utils.py)
        cms = cms or self._sb_idl.get_gateway_chassis_from_cms_options()
        chassis_physnets = (chassis_physnets or
                            self._sb_idl.get_chassis_and_physnets())
        candidates = set()
        for chassis, physnets in chassis_physnets.items():
            if (physnet and
                    physnet in physnets and
                    chassis in cms):
                candidates.add(chassis)
        candidates = list(candidates)

        # Filter for availability zones
        if availability_zone_hints:
            LOG.debug('Filtering Chassis candidates by availability zone '
                      'hints: %s', ', '.join(availability_zone_hints))
            candidates = [ch for ch in candidates
                          for az in availability_zone_hints
                          if az in utils.get_chassis_availability_zones(
                              self._sb_idl.lookup('Chassis', ch, None))]

        LOG.debug('Chassis candidates for scheduling gateway router ports '
                  'for "%s" physical network: %s', physnet, candidates)
        return candidates

    def _get_physnet(self, network):
        if network.get(pnet.NETWORK_TYPE) in [const.TYPE_FLAT,
                                              const.TYPE_VLAN]:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _gen_router_port_ext_ids(self, port, router_id):
        return {
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                port, ovn_const.TYPE_ROUTER_PORTS)),
            ovn_const.OVN_SUBNET_EXT_IDS_KEY:
                ' '.join(utils.get_port_subnet_ids(port)),
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                utils.ovn_name(port['network_id']),
            ovn_const.OVN_ROUTER_IS_EXT_GW:
                str(const.DEVICE_OWNER_ROUTER_GW == port.get('device_owner')),
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                utils.ovn_name(router_id),
        }

    def _get_reside_redir_for_gateway_port(self, context, device_id):
        admin_context = context.elevated()
        reside_redir_ch = 'true'
        if ovn_conf.is_ovn_distributed_floating_ip():
            reside_redir_ch = 'false'
            try:
                router_ports = self._get_router_ports(admin_context, device_id)
            except l3_exc.RouterNotFound:
                LOG.debug("No Router %s not found", device_id)
            else:
                network_ids = {port['network_id'] for port in router_ports}
                networks = self._plugin.get_networks(
                    admin_context, filters={'id': network_ids})

                # NOTE(ltomasbo): not all the networks connected to the router
                # are of vlan type, so we won't set the redirect-type=bridged
                # on the router gateway port, therefore we need to centralized
                # the vlan traffic to avoid tunneling
                if networks:
                    reside_redir_ch = 'true' if any(
                        net.get(pnet.NETWORK_TYPE) not in [const.TYPE_VLAN,
                                                           const.TYPE_FLAT]
                        for net in networks) else 'false'
        return reside_redir_ch

    def _gen_router_port_options(self, context, port):
        options = {}
        admin_context = context.elevated()
        ls_name = utils.ovn_name(port['network_id'])
        ls = self._nb_idl.ls_get(ls_name).execute(check_error=True)
        network_type = ls.external_ids[ovn_const.OVN_NETTYPE_EXT_ID_KEY]
        # For provider networks (VLAN, FLAT types) we need to set the
        # "reside-on-redirect-chassis" option so the routing for this
        # logical router port is centralized in the chassis hosting the
        # distributed gateway port.
        # https://github.com/openvswitch/ovs/commit/85706c34d53d4810f54bec1de662392a3c06a996
        if network_type in [const.TYPE_VLAN, const.TYPE_FLAT]:
            reside_redir_ch = self._get_reside_redir_for_gateway_port(
                admin_context, port['device_id'])
            options[ovn_const.LRP_OPTIONS_RESIDE_REDIR_CH] = reside_redir_ch

        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')

        if is_gw_port:
            try:
                router_ports = self._get_router_ports(admin_context,
                                                      port['device_id'])
            except l3_exc.RouterNotFound:
                # Don't add any mtu info if the router no longer exists
                LOG.debug("Router %s not found", port['device_id'])
            else:
                network_ids = {port['network_id'] for port in router_ports}
                # If this method is called during a port creation, the port
                # won't be present yet in the router ports list. It is
                # needed not to modify the ``network_ids`` set.
                _network_ids = network_ids.union({port['network_id']})
                networks = self._plugin.get_networks(
                    admin_context, filters={'id': _network_ids})
                # Set the lower MTU of all networks connected to the router
                min_mtu = str(min(net['mtu'] for net in networks))
                options[ovn_const.OVN_ROUTER_PORT_GW_MTU_OPTION] = min_mtu
                if ovn_conf.is_ovn_distributed_floating_ip():
                    # NOTE(ltomasbo): For VLAN type networks connected through
                    # the gateway port there is a need to set the redirect-type
                    # option to bridge to ensure traffic is not centralized
                    # through the controller.
                    # If there are no VLAN type networks attached we need to
                    # still make it centralized.
                    enable_redirect = False
                    networks = self._plugin.get_networks(
                        admin_context, filters={'id': network_ids})
                    if networks:
                        enable_redirect = all(
                            net.get(pnet.NETWORK_TYPE) in [const.TYPE_VLAN,
                                                           const.TYPE_FLAT]
                            for net in networks)
                    if enable_redirect:
                        options[ovn_const.LRP_OPTIONS_REDIRECT_TYPE] = (
                            ovn_const.BRIDGE_REDIRECT_TYPE)

        return options

    def _create_lrouter_port(self, context, router, port, txn=None):
        """Create a logical router port."""
        lrouter = utils.ovn_name(router['id'])
        networks, ipv6_ra_configs = (
            self._get_nets_and_ipv6_ra_confs_for_router_port(context, port))
        lrouter_port_name = utils.ovn_lrouter_port_name(port['id'])
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get('device_owner')
        columns = {}
        columns['options'] = self._gen_router_port_options(context, port)

        lsp_address = ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER
        if ipv6_ra_configs:
            columns['ipv6_ra_configs'] = ipv6_ra_configs

        commands = [
            self._nb_idl.add_lrouter_port(
                name=lrouter_port_name,
                lrouter=lrouter,
                mac=port['mac_address'],
                networks=networks,
                may_exist=True,
                external_ids=self._gen_router_port_ext_ids(port, router['id']),
                **columns)
        ]

        if is_gw_port:
            port_net = self._plugin.get_network(
                context.elevated(), port['network_id'])
            physnet = self._get_physnet(port_net)
            if physnet is None:
                # The external network is tunnelled, pin the router to a
                # chassis.
                _, selected_chassis = utils.sync_ha_chassis_group_router(
                    context, self._nb_idl, self._sb_idl, router['id'], txn)
                if selected_chassis:
                    options = {'chassis': selected_chassis}
                    commands.append(self._nb_idl.db_set(
                        'Logical_Router', lrouter, ('options', options)))
                else:
                    LOG.info('Router %s is not pinned to any gateway chassis',
                             router['id'])
            else:
                # VLAN/flat network with a physical network, bind the LRP to
                # a chassis using the OVN L3 scheduler.
                az_hints = common_utils.get_az_hints(router)
                commands.append(
                    self._nb_idl.schedule_new_gateway(lrouter_port_name,
                                                      self._sb_idl,
                                                      lrouter, self._l3_plugin,
                                                      physnet, az_hints))

        commands.append(
            self._nb_idl.set_lrouter_port_in_lswitch_port(
                port['id'], lrouter_port_name, is_gw_port=is_gw_port,
                lsp_address=lsp_address))
        self._transaction(commands, txn=txn)

    def create_router_port(self, context, router_id, router_interface):
        port = self._plugin.get_port(context, router_interface['port_id'])
        router = self._l3_plugin.get_router(context, router_id)
        with self._nb_idl.transaction(check_error=True) as txn:
            multi_prefix = False
            if (len(router_interface.get('subnet_ids', [])) == 1 and
                    len(port['fixed_ips']) > 1):

                # NOTE(lizk) It's adding a subnet onto an already
                # existing router interface port, try to update lrouter port
                # 'networks' column.
                self._update_lrouter_port(context, port, txn=txn)
                multi_prefix = True
            else:
                self._create_lrouter_port(context, router, port, txn=txn)

            gw_ports = self._get_router_gw_ports(context, router_id)
            if gw_ports:
                for gw_port in gw_ports:
                    provider_net = self._plugin.get_network(
                        context, gw_port['network_id'])
                    self.set_gateway_mtu(context, provider_net, txn=txn,
                                         router_id=router_id)

                if _has_separate_snat_per_subnet(router):
                    for fixed_ip in port['fixed_ips']:
                        subnet = self._plugin.get_subnet(
                            context, fixed_ip['subnet_id'])
                        if (multi_prefix and
                                'subnet_id' in router_interface and
                                subnet['id'] != router_interface['subnet_id']):
                            continue
                        if subnet['ip_version'] == const.IP_VERSION_4:
                            self.update_nat_rules(
                                context, router['id'], cidrs=[subnet['cidr']],
                                enable_snat=True, txn=txn)
                            break  # TODO(ihar): handle multiple ipv4 ips?

                if ovn_conf.is_ovn_distributed_floating_ip():
                    router_gw_ports = self._get_router_gw_ports(context,
                                                                router_id)
                    for router_port in router_gw_ports:
                        self._update_lrouter_port(context, router_port,
                                                  txn=txn)

        db_rev.bump_revision(context, port, ovn_const.TYPE_ROUTER_PORTS)

    def _update_lrouter_port(self, context, port, if_exists=False, txn=None):
        """Update a logical router port."""
        networks, ipv6_ra_configs = (
            self._get_nets_and_ipv6_ra_confs_for_router_port(context, port))

        lsp_address = ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER
        lrp_name = utils.ovn_lrouter_port_name(port['id'])
        update = {'networks': networks, 'ipv6_ra_configs': ipv6_ra_configs}
        is_gw_port = const.DEVICE_OWNER_ROUTER_GW == port.get(
            'device_owner')
        external_ids = self._nb_idl.db_get(
            'Logical_Router_Port', lrp_name,
            'external_ids').execute(check_error=True)
        router_id = external_ids[ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY].replace(
            ovn_const.OVN_NAME_PREFIX, '')
        commands = [
            self._nb_idl.update_lrouter_port(
                name=lrp_name,
                external_ids=self._gen_router_port_ext_ids(port, router_id),
                options=self._gen_router_port_options(context, port),
                if_exists=if_exists,
                **update),
            self._nb_idl.set_lrouter_port_in_lswitch_port(
                port['id'], lrp_name, is_gw_port=is_gw_port,
                lsp_address=lsp_address)]

        self._transaction(commands, txn=txn)

    def update_router_port(self, context, port, if_exists=False):
        lrp_name = utils.ovn_lrouter_port_name(port['id'])
        check_rev_cmd = self._nb_idl.check_revision_number(
            lrp_name, port, ovn_const.TYPE_ROUTER_PORTS)
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            self._update_lrouter_port(context, port, if_exists=if_exists,
                                      txn=txn)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(
                context, port, ovn_const.TYPE_ROUTER_PORTS)

    @tenacity.retry(wait=tenacity.wait_random(min=2, max=3),
                    stop=tenacity.stop_after_attempt(3))
    def delete_mac_binding_entries_by_mac(self, mac):
        """Delete all MAC_Binding entries associated to this mac address

        The reason for using ovsdb-client intead of sb_ovn.db_destroy
        is refer to patch:
        https://review.opendev.org/c/openstack/neutron/+/812805
        """
        cmd = [
            "OVN_Southbound", {
                "op": "delete",
                "table": "MAC_Binding",
                "where": [
                    ["mac", "==", mac]
                ]
            }
        ]
        return utils.OvsdbClientTransactCommand.run(cmd)

    def _delete_lrouter_port(self, context, port_id, router_id, txn=None):
        """Delete a logical router port."""
        commands = [self._nb_idl.lrp_del(
            utils.ovn_lrouter_port_name(port_id),
            utils.ovn_name(router_id), if_exists=True)]
        self._transaction(commands, txn=txn)
        db_rev.delete_revision(context, port_id, ovn_const.TYPE_ROUTER_PORTS)

    def delete_router_port(self, context, port_id, subnet_ids=None):
        try:
            ovn_port = self._nb_idl.lookup(
                'Logical_Router_Port', utils.ovn_lrouter_port_name(port_id))
        except idlutils.RowNotFound:
            return

        subnet_ids = subnet_ids or []
        port_removed = False
        port_mac = ovn_port.mac
        with self._nb_idl.transaction(check_error=True) as txn:
            port = None
            try:
                port = self._plugin.get_port(context, port_id)
                # The router interface port still exists, call ovn to
                # update it
                self._update_lrouter_port(context, port, txn=txn)
            except n_exc.PortNotFound:
                # The router interface port doesn't exist any more,
                # we will call ovn to delete it once we remove the snat
                # rules in the router itself if we have to
                port_removed = True

            router_id = ovn_port.external_ids[
                ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY].replace(
                    ovn_const.OVN_NAME_PREFIX, '')
            router = None
            gw_ports = []
            try:
                router = self._l3_plugin.get_router(context, router_id)
                gw_ports = self._get_router_gw_ports(context, router_id)
            except l3_exc.RouterNotFound:
                # If the router is gone, the router port is also gone
                port_removed = True

            if not router or not gw_ports:
                if port_removed:
                    self._delete_lrouter_port(context, port_id, router_id,
                                              txn=txn)
                if port_mac:
                    self.delete_mac_binding_entries_by_mac(port_mac)
                return

            if not subnet_ids:
                subnet_ids = ovn_port.external_ids.get(
                    ovn_const.OVN_SUBNET_EXT_IDS_KEY, [])
                subnet_ids = subnet_ids.split()
            elif port:
                subnet_ids = utils.get_port_subnet_ids(port)

            for gw_port in gw_ports:
                provider_net = self._plugin.get_network(
                    context, gw_port['network_id'])
                self.set_gateway_mtu(context, provider_net, txn=txn,
                                         router_id=router_id)

            if _has_separate_snat_per_subnet(router):
                for sid in subnet_ids:
                    try:
                        subnet = self._plugin.get_subnet(context, sid)
                    except n_exc.SubnetNotFound:
                        continue
                    if subnet['ip_version'] == const.IP_VERSION_4:
                        self.update_nat_rules(
                            context, router['id'], cidrs=[subnet['cidr']],
                            enable_snat=False, txn=txn)
                        break  # TODO(ihar): handle multiple ipv4 ips?

            if ovn_conf.is_ovn_distributed_floating_ip():
                router_gw_ports = self._get_router_gw_ports(context, router_id)
                for router_port in router_gw_ports:
                    self._update_lrouter_port(context, router_port, txn=txn)

            # NOTE(mangelajo): If the port doesn't exist anymore, we
            # delete the router port as the last operation and update the
            # revision database to ensure consistency
            if port_removed:
                self._delete_lrouter_port(context, port_id, router_id, txn=txn)
                if port_mac:
                    self.delete_mac_binding_entries_by_mac(port_mac)
            else:
                # otherwise, we just update the revision database
                db_rev.bump_revision(
                    context, port, ovn_const.TYPE_ROUTER_PORTS)

    def _iter_ipv4_gw_addrs(self, context, router_id):
        yield from (
            gw_info.router_ip
            for gw_port in self._get_router_gw_ports(context, router_id)
            for gw_info in self._get_gw_info(context, gw_port)
            if gw_info.ip_version != const.IP_VERSION_6
        )

    def update_nat_rules(self, context, router_id, enable_snat, cidrs=None,
                         txn=None):
        if enable_snat:
            idl_func = self._nb_idl.add_nat_rule_in_lrouter
        else:
            idl_func = self._nb_idl.delete_nat_rule_in_lrouter
        func = functools.partial(
            idl_func, utils.ovn_name(router_id), type='snat')

        admin_context = context.elevated()
        cidrs = (
            cidrs or
            self._get_snat_cidrs_for_external_router(admin_context, router_id)
        )
        commands = [
            func(logical_ip=cidr, external_ip=router_ip)
            for router_ip in self._iter_ipv4_gw_addrs(admin_context, router_id)
            for cidr in cidrs
        ]
        if not commands:
            return

        self._transaction(commands, txn=txn)

    def create_provnet_port(self, context, network_id, segment, txn=None,
                            network=None):
        tag = segment.get(segment_def.SEGMENTATION_ID, [])
        physnet = segment.get(segment_def.PHYSICAL_NETWORK)
        fdb_enabled = ('true' if ovn_conf.is_learn_fdb_enabled()
                       else 'false')
        options = {
            'network_name': physnet,
            ovn_const.LSP_OPTIONS_MCAST_FLOOD_REPORTS:
                ovs_conf.get_igmp_flood_reports(),
            ovn_const.LSP_OPTIONS_MCAST_FLOOD:
                ovs_conf.get_igmp_flood(),
            ovn_const.LSP_OPTIONS_LOCALNET_LEARN_FDB: fdb_enabled}
        network = network or self._plugin.get_network(
            context.elevated(), network_id)
        if self._get_vlan_passthru(network):
            vlan_ethtype = self._get_vlan_ethtype(network)
            if vlan_ethtype == ovn_const.ETHTYPE_8021ad:
                # 802.1q ethtype is default so it needs to be set in the OVN
                # db only if required value is 802.1ad
                options[ovn_const.VLAN_ETHTYPE] = vlan_ethtype

        cmd = self._nb_idl.create_lswitch_port(
            lport_name=utils.ovn_provnet_port_name(segment['id']),
            lswitch_name=utils.ovn_name(network_id),
            network_id=network_id,
            addresses=[ovn_const.UNKNOWN_ADDR],
            external_ids={},
            type=ovn_const.LSP_TYPE_LOCALNET,
            tag=tag,
            options=options)
        self._transaction([cmd], txn=txn)

    def delete_provnet_port(self, network_id, segment):
        port_to_del = utils.ovn_provnet_port_name(segment['id'])
        cmd = self._nb_idl.delete_lswitch_port(
            lport_name=port_to_del,
            lswitch_name=utils.ovn_name(network_id))
        self._transaction([cmd])

    def _get_vlan_passthru(self, network):
        return bool(network.get('vlan_transparent') or
                    network.get(qinq_apidef.QINQ_FIELD))

    def _get_vlan_ethtype(self, network):
        return (ovn_const.ETHTYPE_8021ad if network.get(qinq_apidef.QINQ_FIELD)
                else ovn_const.ETHTYPE_8021q)

    def _gen_network_parameters(self,
                                network: dict) -> dict[str, dict[str, str]]:
        ext_ids = {
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network['name'],
            ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY: network['mtu'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY:
                utils.get_revision_number(network, ovn_const.TYPE_NETWORKS),
            ovn_const.OVN_AZ_HINTS_EXT_ID_KEY:
                ','.join(common_utils.get_az_hints(network)),
            # NOTE(ralonsoh): it is not considered the case of multiple
            # segments.
            # NOTE(twilson): in the case of multiple segments, or when all
            # segments are removed, NETWORK_TYPE=None, which is invalid ovsdb
            ovn_const.OVN_NETTYPE_EXT_ID_KEY: network.get(pnet.NETWORK_TYPE),
            ovn_const.OVN_PHYSNET_EXT_ID_KEY:
                network.get(pnet.PHYSICAL_NETWORK),
        }

        # Enable IGMP snooping if igmp_snooping_enable is enabled in Neutron
        other_config = {
            ovn_const.MCAST_SNOOP:
                ovs_conf.get_igmp_snooping_enabled(),
            ovn_const.MCAST_FLOOD_UNREGISTERED:
                ovs_conf.get_igmp_flood_unregistered(),
            ovn_const.VLAN_PASSTHRU: str(
                self._get_vlan_passthru(network)).lower()}
        if utils.is_provider_network(network):
            other_config[ovn_const.LS_OPTIONS_FDB_AGE_THRESHOLD] = (
                ovn_conf.get_fdb_age_threshold())
        if utils.is_external_network(network):
            other_config[ovn_const.LS_OPTIONS_BROADCAST_ARPS_ROUTERS] = (
                'true'
                if ovn_conf.is_broadcast_arps_to_all_routers_enabled() else
                'false')
        return {'external_ids': common_utils.stringmap(ext_ids),
                'other_config': common_utils.stringmap(other_config)}

    def create_network(self, context, network):
        # Create a logical switch with a name equal to the Neutron network
        # UUID.  This provides an easy way to refer to the logical switch
        # without having to track what UUID OVN assigned to it.
        lswitch_params = self._gen_network_parameters(network)
        # NOTE(mjozefcz): Remove this workaround when bug
        # 1869877 will be fixed.
        segments = segments_db.get_network_segments(
            context, network['id'])
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.ls_add(network_id=network['id'],
                                        **lswitch_params, may_exist=True))
            for segment in segments:
                if segment.get(segment_def.PHYSICAL_NETWORK):
                    self.create_provnet_port(context, network['id'], segment,
                                             txn=txn, network=network)
        db_rev.bump_revision(context, network, ovn_const.TYPE_NETWORKS)
        self.create_metadata_port(context, network)
        return network

    def delete_network(self, context, network_id):
        self._nb_idl.ls_del(utils.ovn_name(network_id),
                            if_exists=True).execute(check_error=True)
        db_rev.delete_revision(
            context, network_id, ovn_const.TYPE_NETWORKS)

    def set_gateway_mtu(self, context, prov_net, txn=None,
                        router_id=None):
        _filters = {'network_id': [prov_net['id']],
                    'device_owner': [const.DEVICE_OWNER_ROUTER_GW]}
        if router_id:
            _filters['device_id'] = [router_id]
        ports = self._plugin.get_ports(context, filters=_filters)
        commands = []
        for port in ports:
            lrp_name = utils.ovn_lrouter_port_name(port['id'])
            options = self._gen_router_port_options(context, port)
            # Do not fail for cases where logical router port get deleted
            commands.append(self._nb_idl.lrp_set_options(lrp_name,
                                                         if_exists=True,
                                                         **options))
        self._transaction(commands, txn=txn)

    def _check_network_changes_in_ha_chassis_groups(
            self, context, lswitch, lswitch_params, txn):
        """Check for changes in the HA Chassis Groups.

        Check for changes in the HA Chassis Groups upon a network update.
        """
        # Check for changes in the network Availability Zones
        ovn_ls_azs = lswitch.external_ids.get(
            ovn_const.OVN_AZ_HINTS_EXT_ID_KEY, '')
        neutron_net_azs = lswitch_params['external_ids'].get(
            ovn_const.OVN_AZ_HINTS_EXT_ID_KEY, '')

        # Check if there are changes to the AZs
        if ovn_ls_azs != neutron_net_azs:
            return

        extport_list = [p for p in lswitch.ports if
                        p.type == ovn_const.LSP_TYPE_EXTERNAL]

        # Check if there are dedicated chassis for external ports
        if self._sb_idl.get_extport_chassis_from_cms_options():
            for extport in extport_list:
                port_id = extport.name
                network_id = extport.external_ids[
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY].replace(
                        ovn_const.OVN_NAME_PREFIX, '')
                utils.sync_ha_chassis_group_network(
                    context, self._nb_idl, self._sb_idl, port_id, network_id,
                    txn)
        elif extport_list:
            # If there's no dedicated chassis for external ports, there will
            # be 1 HA Chassis Group per network, so the sync is at the network
            # level. Just pass any external port from that network to the
            # sync method
            port_id = extport_list[0].name
            network_id = extport_list[0].external_ids[
                ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY].replace(
                    ovn_const.OVN_NAME_PREFIX, '')
            utils.sync_ha_chassis_group_network(
                context, self._nb_idl, self._sb_idl, port_id, network_id, txn)

    def update_network(self, context, network, original_network=None):
        lswitch_name = utils.ovn_name(network['id'])
        check_rev_cmd = self._nb_idl.check_revision_number(
            lswitch_name, network, ovn_const.TYPE_NETWORKS)

        # TODO(numans) - When a network's dns domain name is updated, we need
        # to update the DNS records for this network in DNS OVN NB DB table.
        # (https://bugs.launchpad.net/networking-ovn/+bug/1777978)
        # Eg. if the network n1's dns domain name was "test1" and if it has
        # 2 bound ports - p1 and p2, we would have created the below dns
        # records
        # ===========================
        # p1 = P1_IP
        # p1.test1 = P1_IP
        # p1.default_domain = P1_IP
        # p2 = P2_IP
        # p2.test1 = P2_IP
        # p2.default_domain = P2_IP
        # ===========================
        # if the network n1's dns domain name is updated to test2, then we need
        # to delete the below DNS records
        # ===========================
        # p1.test1 = P1_IP
        # p2.test1 = P2_IP
        # ===========================
        # and add the new ones
        # ===========================
        # p1.test2 = P1_IP
        # p2.test2 = P2_IP
        # ===========================
        # in the DNS row for this network.

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(check_rev_cmd)
            lswitch_params = self._gen_network_parameters(network)
            lswitch = self._nb_idl.get_lswitch(lswitch_name)
            txn.add(self._nb_idl.db_set(
                'Logical_Switch', lswitch_name, *lswitch_params.items()))
            # Check if previous mtu is different than current one,
            # checking will help reduce number of operations
            if (not lswitch or
                    lswitch.external_ids.get(
                        ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY) !=
                    str(network['mtu'])):
                subnets = self._plugin.get_subnets_by_network(
                    context, network['id'])
                for subnet in subnets:
                    self.update_subnet(context, subnet, network, txn)

                if utils.is_external_network(network):
                    # make sure to use admin context as this is a external
                    # network
                    self.set_gateway_mtu(context.elevated(), network, txn=txn)

            self._check_network_changes_in_ha_chassis_groups(
                context, lswitch, lswitch_params, txn)

            # Update the segment tags, if any
            segments = segments_db.get_network_segments(context, network['id'])
            for segment in segments:
                tag = segment.get(segment_def.SEGMENTATION_ID)
                tag = [] if tag is None else tag
                lport_name = utils.ovn_provnet_port_name(segment['id'])
                txn.add(self._nb_idl.set_lswitch_port(lport_name=lport_name,
                                                      tag=tag, if_exists=True))

            self._qos_driver.update_network(context, txn, network,
                                            original_network)

        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(context, network, ovn_const.TYPE_NETWORKS)

    def _add_subnet_dhcp_options(self, context, subnet, network,
                                 ovn_dhcp_options=None):
        if utils.is_dhcp_options_ignored(subnet):
            return

        if not ovn_dhcp_options:
            ovn_dhcp_options = self._get_ovn_dhcp_options(context, subnet,
                                                          network)

        with self._nb_idl.transaction(check_error=True) as txn:
            rev_num = {ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(
                utils.get_revision_number(subnet, ovn_const.TYPE_SUBNETS))}
            ovn_dhcp_options['external_ids'].update(rev_num)
            txn.add(self._nb_idl.add_dhcp_options(subnet['id'],
                                                  **ovn_dhcp_options))

    def _get_ovn_dhcp_options(self, context, subnet, network, server_mac=None):
        external_ids = {
            'subnet_id': subnet['id'],
            ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(utils.get_revision_number(
                subnet, ovn_const.TYPE_SUBNETS))}
        dhcp_options = {'cidr': subnet['cidr'], 'options': {},
                        'external_ids': external_ids}

        if subnet['enable_dhcp']:
            if subnet['ip_version'] == const.IP_VERSION_4:
                dhcp_options['options'] = self._get_ovn_dhcpv4_opts(
                    context, subnet, network, server_mac=server_mac)
            else:
                dhcp_options['options'] = self._get_ovn_dhcpv6_opts(
                    subnet, server_id=server_mac)

        return dhcp_options

    def _process_global_dhcp_opts(self, options, ip_version):
        if ip_version == const.IP_VERSION_4:
            global_options = ovn_conf.get_global_dhcpv4_opts()
        else:
            global_options = ovn_conf.get_global_dhcpv6_opts()

        for option, value in global_options.items():
            if option in ovn_const.GLOBAL_DHCP_OPTS_PROHIBIT_LIST[ip_version]:
                # This option is not allowed to be set with a global setting
                LOG.debug('DHCP option %s is not permitted to be set in '
                          'global options. This option will be ignored.',
                          option)
                continue
            # If the value is null (i.e. config ntp_server:), treat it as
            # a request to remove the option
            if value:
                # Example: ntp_server='{1.2.3.4, 1.2.3.5}'. A single value is
                # also allowed but in shake of readability, it is printed as a
                # single string.
                _value = value.split(';')
                options[option] = (_value[0] if len(_value) == 1 else
                                   '{%s}' % ', '.join(_value))
            else:
                try:
                    del options[option]
                except KeyError:
                    # Option not present, job done
                    pass

    def _get_ovn_dhcpv4_opts(self, context, subnet, network, server_mac=None):
        metadata_port_ip = self._find_metadata_port_ip(
            context.elevated(), subnet)
        # TODO(dongj): Currently the metadata port is created only when
        # ovn_metadata_enabled is true, therefore this is a restriction for
        # supporting DHCP of subnet without gateway IP.
        # We will remove this restriction later.
        service_id = subnet['gateway_ip'] or metadata_port_ip
        if not service_id:
            return {}

        default_lease_time = str(ovn_conf.get_ovn_dhcp_default_lease_time())
        mtu = network['mtu']
        options = {
            'server_id': service_id,
            'lease_time': default_lease_time,
            'mtu': str(mtu),
        }

        if cfg.CONF.dns_domain and cfg.CONF.dns_domain != 'openstacklocal':
            # NOTE(mjozefcz): String field should be with quotes,
            # otherwise ovn will try to resolve it as variable.
            options['domain_name'] = '"%s"' % cfg.CONF.dns_domain

        if subnet['gateway_ip']:
            options['router'] = subnet['gateway_ip']

        if server_mac:
            options['server_mac'] = server_mac
        else:
            options['server_mac'] = n_net.get_random_mac(
                cfg.CONF.base_mac.split(':'))

        dns_servers = utils.get_dhcp_dns_servers(subnet)
        if dns_servers:
            options['dns_server'] = '{%s}' % ', '.join(dns_servers)
        else:
            LOG.warning("No relevant dns_servers defined for subnet %s. Check "
                        "the /etc/resolv.conf file",
                        subnet['id'])

        routes = []
        if metadata_port_ip:
            routes.append('{},{}'.format(
                const.METADATA_V4_CIDR, metadata_port_ip))

        # Add subnet host_routes to 'classless_static_route' dhcp option
        routes.extend(['{},{}'.format(route['destination'], route['nexthop'])
                       for route in subnet['host_routes']])

        if routes:
            # if there are static routes, then we need to add the
            # default route in this option. As per RFC 3442 dhcp clients
            # should ignore 'router' dhcp option (option 3)
            # if option 121 is present.
            if subnet['gateway_ip']:
                routes.append('0.0.0.0/0,%s' % subnet['gateway_ip'])

            options['classless_static_route'] = '{' + ', '.join(routes) + '}'

        self._process_global_dhcp_opts(options, ip_version=const.IP_VERSION_4)

        return options

    def _get_ovn_dhcpv6_opts(self, subnet, server_id=None):
        """Returns the DHCPv6 options"""

        dhcpv6_opts = {
            'server_id': server_id or n_net.get_random_mac(
                cfg.CONF.base_mac.split(':'))
        }

        dns_servers = utils.get_dhcp_dns_servers(subnet,
                                                 ip_version=const.IP_VERSION_6)
        if dns_servers:
            dhcpv6_opts['dns_server'] = '{%s}' % ', '.join(dns_servers)

        if subnet.get('ipv6_address_mode') == const.DHCPV6_STATELESS:
            dhcpv6_opts[ovn_const.DHCPV6_STATELESS_OPT] = 'true'

        self._process_global_dhcp_opts(dhcpv6_opts,
                                       ip_version=const.IP_VERSION_6)

        return dhcpv6_opts

    def _remove_subnet_dhcp_options(self, subnet_id, txn):
        dhcp_options = self._nb_idl.get_subnet_dhcp_options(
            subnet_id, with_ports=True)

        if dhcp_options['subnet']:
            txn.add(self._nb_idl.delete_dhcp_options(
                dhcp_options['subnet']['uuid']))

        # Remove subnet and port DHCP_Options rows, the DHCP options in
        # lsp rows will be removed by related UUID
        for opt in dhcp_options['ports']:
            txn.add(self._nb_idl.delete_dhcp_options(opt['uuid']))

    def _enable_subnet_dhcp_options(self, context, subnet, network, txn):
        if utils.is_dhcp_options_ignored(subnet):
            return

        filters = {'fixed_ips': {'subnet_id': [subnet['id']]}}
        all_ports = self._plugin.get_ports(context.elevated(), filters=filters)
        ports = [p for p in all_ports if not utils.is_network_device_port(p)]

        dhcp_options = self._get_ovn_dhcp_options(context, subnet, network)
        subnet_dhcp_cmd = self._nb_idl.add_dhcp_options(subnet['id'],
                                                        **dhcp_options)
        subnet_dhcp_option = txn.add(subnet_dhcp_cmd)
        # Traverse ports to add port DHCP_Options rows
        for port in ports:
            lsp_dhcp_disabled, lsp_dhcp_opts = utils.get_lsp_dhcp_opts(
                port, subnet['ip_version'])
            if lsp_dhcp_disabled:
                continue
            if not lsp_dhcp_opts:
                lsp_dhcp_options = subnet_dhcp_option
            else:
                port_dhcp_options = copy.deepcopy(dhcp_options)
                port_dhcp_options['options'].update(lsp_dhcp_opts)
                port_dhcp_options['external_ids'].update(
                    {'port_id': port['id']})
                lsp_dhcp_options = txn.add(self._nb_idl.add_dhcp_options(
                    subnet['id'], port_id=port['id'],
                    **port_dhcp_options))
            columns = ({'dhcpv6_options': lsp_dhcp_options} if
                       subnet['ip_version'] == const.IP_VERSION_6 else {
                           'dhcpv4_options': lsp_dhcp_options})

            # Set lsp DHCP options
            txn.add(self._nb_idl.set_lswitch_port(
                lport_name=port['id'], **columns))

    def _update_subnet_dhcp_options(self, context, subnet, network, txn):
        if utils.is_dhcp_options_ignored(subnet):
            return
        original_options = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'])['subnet']
        mac = None
        if original_options:
            if subnet['ip_version'] == const.IP_VERSION_6:
                mac = original_options['options'].get('server_id')
            else:
                mac = original_options['options'].get('server_mac')
        new_options = self._get_ovn_dhcp_options(context, subnet, network, mac)
        # Check whether DHCP changed
        if (original_options and
                original_options['cidr'] == new_options['cidr'] and
                original_options['options'] == new_options['options']):
            return
        txn.add(self._nb_idl.add_dhcp_options(subnet['id'], **new_options))
        dhcp_options = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'], with_ports=True)

        # When a subnet dns_nameserver is updated, then we should update
        # the port dhcp options for ports (with no port specific dns_server
        # defined).
        if 'options' in new_options and 'options' in original_options:
            orig_dns_server = original_options['options'].get('dns_server')
            new_dns_server = new_options['options'].get('dns_server')
            dns_server_changed = (orig_dns_server != new_dns_server)
        else:
            dns_server_changed = False

        for opt in dhcp_options['ports']:
            if not new_options.get('options'):
                continue
            options = dict(new_options['options'])
            p_dns_server = opt['options'].get('dns_server')
            if dns_server_changed and (orig_dns_server == p_dns_server):
                # If port has its own dns_server option defined, then
                # orig_dns_server and p_dns_server will not match.
                opt['options']['dns_server'] = new_dns_server
            options.update(opt['options'])

            port_id = opt['external_ids']['port_id']
            txn.add(self._nb_idl.add_dhcp_options(
                subnet['id'], port_id=port_id, options=options))

    def create_subnet(self, context, subnet, network):
        if subnet['enable_dhcp']:
            mport_updated = False
            if subnet['ip_version'] == const.IP_VERSION_4:
                mport_updated = self.update_metadata_port(
                    context, network, subnet=subnet)
            if subnet['ip_version'] == const.IP_VERSION_6 or not mport_updated:
                # NOTE(ralonsoh): if IPv4 but the metadata port has not been
                # updated, the DHPC options register has not been created.
                self._add_subnet_dhcp_options(context, subnet, network)
        db_rev.bump_revision(context, subnet, ovn_const.TYPE_SUBNETS)

    def _modify_subnet_dhcp_options(self, context, subnet, ovn_subnet, network,
                                    txn):
        if subnet['enable_dhcp'] and not ovn_subnet:
            self._enable_subnet_dhcp_options(context, subnet, network, txn)
        elif subnet['enable_dhcp'] and ovn_subnet:
            self._update_subnet_dhcp_options(
                context, subnet, network, txn)
        elif not subnet['enable_dhcp'] and ovn_subnet:
            self._remove_subnet_dhcp_options(subnet['id'], txn)

    def update_subnet(self, context, subnet, network, txn=None):
        ovn_subnet = self._nb_idl.get_subnet_dhcp_options(
            subnet['id'])['subnet']

        if subnet['enable_dhcp'] or ovn_subnet:
            self.update_metadata_port(context, network, subnet=subnet)

        check_rev_cmd = self._nb_idl.check_revision_number(
            subnet['id'], subnet, ovn_const.TYPE_SUBNETS)
        if not txn:
            with self._nb_idl.transaction(check_error=True) as txn_n:
                txn_n.add(check_rev_cmd)
                self._modify_subnet_dhcp_options(context, subnet, ovn_subnet,
                                                 network, txn_n)
        else:
            self._modify_subnet_dhcp_options(context, subnet, ovn_subnet,
                                             network, txn)
        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(context, subnet, ovn_const.TYPE_SUBNETS)

    def delete_subnet(self, context, subnet_id):
        with self._nb_idl.transaction(check_error=True) as txn:
            self._remove_subnet_dhcp_options(subnet_id, txn)
        db_rev.delete_revision(
            context, subnet_id, ovn_const.TYPE_SUBNETS)

    def create_security_group(self, context, security_group):
        with self._nb_idl.transaction(check_error=True) as txn:
            ext_ids = {ovn_const.OVN_SG_EXT_ID_KEY: security_group['id']}
            name = utils.ovn_port_group_name(security_group['id'])
            txn.add(self._nb_idl.pg_add(
                name=name, acls=[], external_ids=ext_ids))
            # When a SG is created, it comes with some default rules,
            # so we'll apply them to the Port Group.
            ovn_acl.add_acls_for_sg_port_group(
                self._nb_idl, security_group, txn)
        db_rev.bump_revision(
            context, security_group, ovn_const.TYPE_SECURITY_GROUPS)
        for sg_rule in security_group['security_group_rules']:
            db_rev.bump_revision(
                context, sg_rule, ovn_const.TYPE_SECURITY_GROUP_RULES)

    def _add_port_to_drop_port_group(self, port, txn):
        txn.add(self._nb_idl.pg_add_ports(ovn_const.OVN_DROP_PORT_GROUP_NAME,
                                          port))

    def _del_port_from_drop_port_group(self, port, txn):
        pg_name = ovn_const.OVN_DROP_PORT_GROUP_NAME
        if self._nb_idl.get_port_group(pg_name):
            txn.add(self._nb_idl.pg_del_ports(pg_name, port))

    def delete_security_group(self, context, security_group_id,
                              delete_sg_rules=False):
        """Delete the OVN port group related to a Neutron security group

        The Port_Group deletion also implies the deletion of the ACLs (security
        group rules). If the flag delete_sg_rules is enabled, it is needed to
        remove the security rule revision numbers.
        """
        name = utils.ovn_port_group_name(security_group_id)
        pg = self._nb_idl.pg_get(name).execute(check_error=True)
        sg_rule_ids = [acl.external_ids[ovn_const.OVN_SG_RULE_EXT_ID_KEY]
                       for acl in pg.acls]
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.pg_del(name=name, if_exists=True))
        db_rev.delete_revision(context, security_group_id,
                               ovn_const.TYPE_SECURITY_GROUPS)
        if delete_sg_rules:
            db_rev.delete_revisions(context, sg_rule_ids,
                                    ovn_const.TYPE_SECURITY_GROUP_RULES)

    def _process_security_group_rule(self, context, rule, is_add_acl=True):
        ovn_acl.update_acls_for_security_group(
            self._plugin, context.elevated(), self._nb_idl,
            rule['security_group_id'], rule,
            is_add_acl=is_add_acl)

    def create_security_group_rule(self, context, rule):
        self._process_security_group_rule(context, rule)
        db_rev.bump_revision(
            context, rule, ovn_const.TYPE_SECURITY_GROUP_RULES)

    def delete_security_group_rule(self, context, rule):
        self._process_security_group_rule(context, rule, is_add_acl=False)
        db_rev.delete_revision(
            context, rule['id'], ovn_const.TYPE_SECURITY_GROUP_RULES)

    def _checkout_ip_list(self, addresses):
        """Return address map for addresses.

        This method will check out ipv4 and ipv6 address list from the
        given address list.
        Eg. if addresses = ["192.168.2.2/32", "2001:db8::/32"], it will
        return {"4":["192.168.2.2/32"], "6":["2001:db8::/32"]}.

        :param addresses: address list.
        """
        if not addresses:
            addresses = []
        ip_addresses = [netaddr.IPNetwork(ip)
                        for ip in addresses]
        addr_map = {const.IP_VERSION_4: [], const.IP_VERSION_6: []}
        for addr in ip_addresses:
            addr_map[addr.version].append(str(addr.cidr))
        return addr_map

    def create_address_group(self, context, address_group):
        addr_map_all = self._checkout_ip_list(
            address_group.get('addresses'))
        external_ids = {ovn_const.OVN_ADDRESS_GROUP_ID_KEY:
                        address_group['id'],
                        ovn_const.OVN_REV_NUM_EXT_ID_KEY: str(
                            utils.get_revision_number(
                                address_group,
                                ovn_const.TYPE_ADDRESS_GROUPS))
                        }
        attrs = [('external_ids', external_ids),]
        for ip_version in const.IP_ALLOWED_VERSIONS:
            as_name = utils.ovn_ag_addrset_name(address_group['id'],
                                                'ip' + str(ip_version))
            with self._nb_idl.transaction(check_error=True) as txn:
                txn.add(self._nb_idl.address_set_add(
                    as_name, addresses=addr_map_all[ip_version],
                    may_exist=True))
                txn.add(self._nb_idl.db_set(
                    'Address_Set', as_name, *attrs))
        db_rev.bump_revision(
            context, address_group, ovn_const.TYPE_ADDRESS_GROUPS)

    def update_address_group(self, context, address_group):
        addr_map_db = self._checkout_ip_list(address_group['addresses'])
        for ip_version in const.IP_ALLOWED_VERSIONS:
            as_name = utils.ovn_ag_addrset_name(address_group['id'],
                                                'ip' + str(ip_version))
            check_rev_cmd = self._nb_idl.check_revision_number(
                as_name, address_group, ovn_const.TYPE_ADDRESS_GROUPS)
            with self._nb_idl.transaction(check_error=True) as txn:
                txn.add(check_rev_cmd)
                # For add/remove addresses
                addr_ovn = self._nb_idl.get_address_set(as_name)[0].addresses
                added = set(addr_map_db[ip_version]) - set(addr_ovn)
                removed = set(addr_ovn) - set(addr_map_db[ip_version])
                txn.add(self._nb_idl.address_set_add_addresses(
                    as_name,
                    added
                ))
                txn.add(self._nb_idl.address_set_remove_addresses(
                    as_name,
                    removed
                ))
        if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
            db_rev.bump_revision(
                context, address_group, ovn_const.TYPE_ADDRESS_GROUPS)

    def delete_address_group(self, context, address_group_id):
        ipv4_as_name = utils.ovn_ag_addrset_name(address_group_id, 'ip4')
        ipv6_as_name = utils.ovn_ag_addrset_name(address_group_id, 'ip6')
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(self._nb_idl.address_set_del(
                ipv4_as_name, if_exists=True))
            txn.add(self._nb_idl.address_set_del(
                ipv6_as_name, if_exists=True))
        db_rev.delete_revision(
            context, address_group_id, ovn_const.TYPE_ADDRESS_GROUPS)

    def _find_metadata_port(self, context, network_id):
        if not ovn_conf.is_ovn_metadata_enabled():
            return

        ports = self._plugin.get_ports(
            context, filters=dict(
                network_id=[network_id],
                device_owner=[const.DEVICE_OWNER_DISTRIBUTED]),
            limit=1)

        if ports:
            return ports[0]

    def _find_metadata_port_ip(self, context, subnet):
        metadata_port = self._find_metadata_port(context, subnet['network_id'])
        if metadata_port:
            for fixed_ip in metadata_port['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    return fixed_ip['ip_address']

    def create_metadata_port(self, context, network):
        if not ovn_conf.is_ovn_metadata_enabled():
            return

        net_id = network['id']
        metadata_port = self._find_metadata_port(context, net_id)
        if metadata_port:
            return metadata_port

        # Create a neutron port for DHCP/metadata services
        filters = {'network_id': [net_id]}
        subnets = self._plugin.get_subnets(context, filters=filters)
        fixed_ips = [{'subnet_id': s['id']}
                     for s in subnets if s['enable_dhcp']]
        port = {'port': {'network_id': net_id,
                         'tenant_id': network['project_id'],
                         'device_owner': const.DEVICE_OWNER_DISTRIBUTED,
                         'device_id': ovn_const.OVN_METADATA_PREFIX + net_id,
                         'fixed_ips': fixed_ips,
                         }
                }
        return p_utils.create_port(self._plugin, context, port)

    def update_metadata_port(self, context, network, subnet=None):
        """Update metadata port.

        This function will allocate an IP address for the metadata port of
        the given network in all its IPv4 subnets or the given subnet. Returns
        "True" if the metadata port has been updated and "False" if OVN
        metadata is disabled or the metadata port does not exist or
        cannot be created.
        """
        network_id = network['id']

        def update_metadata_port_fixed_ips(metadata_port, add_subnet_ids,
                                           del_subnet_ids):
            wanted_fixed_ips = [
                {'subnet_id': fixed_ip['subnet_id'],
                 'ip_address': fixed_ip['ip_address']} for fixed_ip in
                metadata_port['fixed_ips'] if
                fixed_ip['subnet_id'] not in del_subnet_ids]
            wanted_fixed_ips.extend({'subnet_id': s_id} for s_id in
                                    add_subnet_ids)
            port = {'id': metadata_port['id'],
                    'port': {'network_id': network_id,
                             'fixed_ips': wanted_fixed_ips}}
            self._plugin.update_port(
                context.elevated(), metadata_port['id'], port)

        if not ovn_conf.is_ovn_metadata_enabled():
            return False

        # Retrieve or create the metadata port of this network
        metadata_port = self.create_metadata_port(context, network)
        if not metadata_port:
            LOG.error("Metadata port could not be found or created "
                      "for network %s", network_id)
            return False

        port_subnet_ids = {ip['subnet_id'] for ip in
                           metadata_port['fixed_ips']}

        # If this method is called from "create_subnet" or "update_subnet",
        # only the fixed IP address from this subnet should be updated in the
        # metadata port.
        if subnet and subnet['id']:
            if subnet['enable_dhcp'] and subnet['id'] not in port_subnet_ids:
                update_metadata_port_fixed_ips(metadata_port,
                                               [subnet['id']], [])
            elif not subnet['enable_dhcp'] and subnet['id'] in port_subnet_ids:
                update_metadata_port_fixed_ips(metadata_port,
                                               [], [subnet['id']])
            return True

        # Retrieve all subnets in this network
        subnets = self._plugin.get_subnets(context, filters=dict(
            network_id=[network_id], ip_version=[const.IP_VERSION_4],
            enable_dhcp=[True]))

        subnet_ids = {s['id'] for s in subnets}

        # Find all subnets where metadata port doesn't have an IP in and
        # allocate one.
        if subnet_ids != port_subnet_ids:
            update_metadata_port_fixed_ips(metadata_port,
                                           subnet_ids - port_subnet_ids,
                                           port_subnet_ids - subnet_ids)

        return True

    def get_parent_port(self, port_id):
        return self._nb_idl.get_parent_port(port_id)

    def is_dns_required_for_port(self, port):
        try:
            if not all([port['dns_name'], port['dns_assignment'],
                        port['device_id']]):
                return False
        except KeyError:
            # Possible that dns extension is not enabled.
            return False

        if not self._nb_idl.is_table_present('DNS'):
            return False

        return True

    def get_port_dns_records(self, port):
        port_dns_records = {}
        net = port.get('network', {})
        net_dns_domain = net.get('dns_domain', '').rstrip('.')

        for dns_assignment in port.get('dns_assignment', []):
            hostname = dns_assignment['hostname']
            fqdn = dns_assignment['fqdn'].rstrip('.')
            net_dns_fqdn = hostname + '.' + net_dns_domain
            if hostname not in port_dns_records:
                port_dns_records[hostname] = dns_assignment['ip_address']
                if net_dns_domain and net_dns_fqdn != fqdn:
                    port_dns_records[net_dns_fqdn] = (
                        dns_assignment['ip_address'])
            else:
                port_dns_records[hostname] += " " + (
                    dns_assignment['ip_address'])
                if net_dns_domain and net_dns_fqdn != fqdn:
                    port_dns_records[hostname + '.' + net_dns_domain] += (
                        " " + dns_assignment['ip_address'])

            if fqdn not in port_dns_records:
                port_dns_records[fqdn] = dns_assignment['ip_address']
            else:
                port_dns_records[fqdn] += " " + dns_assignment['ip_address']
            # Add reverse DNS entries for port only for fqdn
            for ip in port_dns_records[fqdn].split(" "):
                ptr_record = netaddr.IPAddress(ip).reverse_dns.rstrip(".")
                port_dns_records[ptr_record] = fqdn

        return port_dns_records

    def add_txns_to_sync_port_dns_records(self, txn, port, original_port=None):
        # NOTE(numans): - This implementation has certain known limitations
        # and that will be addressed in the future patches
        # https://bugs.launchpad.net/networking-ovn/+bug/1739257.
        # Please see the bug report for more information, but just to sum up
        # here
        #  - We will have issues if two ports have same dns name
        #  - If a port is deleted with dns name 'd1' and a new port is
        #    added with the same dns name 'd1'.
        records_to_add = self.get_port_dns_records(port)
        lswitch_name = utils.ovn_name(port['network_id'])
        ls, ls_dns_record = self._nb_idl.get_ls_and_dns_record(lswitch_name)

        # If ls_dns_record is None, then we need to create a DNS row for the
        # logical switch.
        if ls_dns_record is None:
            dns_add_txn = txn.add(self._nb_idl.dns_add(
                external_ids={'ls_name': ls.name}, records=records_to_add))
            txn.add(self._nb_idl.ls_set_dns_records(ls.uuid, dns_add_txn))
            return

        # Only run when options column is available
        if hasattr(ls_dns_record, 'options'):
            ovn_owned = ('true' if ovn_conf.is_dns_records_ovn_owned()
                         else 'false')
            dns_options = {ovn_const.OVN_OWNED: ovn_owned}
            txn.add(self._nb_idl.dns_set_options(ls_dns_record.uuid,
                    **dns_options))

        if original_port:
            old_records = self.get_port_dns_records(original_port)

            for old_hostname, old_ips in old_records.items():
                if records_to_add.get(old_hostname) != old_ips:
                    txn.add(self._nb_idl.dns_remove_record(
                        ls_dns_record.uuid, old_hostname, if_exists=True))

        for hostname, ips in records_to_add.items():
            if ls_dns_record.records.get(hostname) != ips:
                txn.add(self._nb_idl.dns_add_record(
                    ls_dns_record.uuid, hostname, ips))

    def add_txns_to_remove_port_dns_records(self, txn, port):
        lswitch_name = utils.ovn_name(port['network_id'])
        ls, ls_dns_record = self._nb_idl.get_ls_and_dns_record(lswitch_name)

        if ls_dns_record is None:
            return

        net = port.get('network', {})
        net_dns_domain = net.get('dns_domain', '').rstrip('.')

        hostnames = []
        ips = []
        for dns_assignment in port['dns_assignment']:
            hostname = dns_assignment['hostname']
            fqdn = dns_assignment['fqdn'].rstrip('.')
            ip = dns_assignment['ip_address']
            if hostname not in hostnames:
                hostnames.append(hostname)
                net_dns_fqdn = hostname + '.' + net_dns_domain
                if net_dns_domain and net_dns_fqdn != fqdn:
                    hostnames.append(net_dns_fqdn)
            if ip not in ips:
                ips.append(ip)

            if fqdn not in hostnames:
                hostnames.append(fqdn)

        for hostname in hostnames:
            if ls_dns_record.records.get(hostname):
                txn.add(self._nb_idl.dns_remove_record(
                    ls_dns_record.uuid, hostname, if_exists=True))
        for ip in ips:
            ptr_record = netaddr.IPAddress(ip).reverse_dns.rstrip(".")
            if ls_dns_record.records.get(ptr_record):
                txn.add(self._nb_idl.dns_remove_record(
                    ls_dns_record.uuid, ptr_record, if_exists=True))

    def _create_ovn_fair_meter(self, meter_name, from_reload=False, txn=None,
                               stateless=False):
        """Create row in Meter table with fair attribute set to True.

        Create a row in OVN's NB Meter table based on well-known name. This
        method uses the network_log configuration to specify the attributes
        of the meter. Current implementation needs only one 'fair' meter row
        which is then referred by multiple ACL rows.

        :param meter_name: ovn northbound meter name.
        :param from_reload: whether we update the meter values or create them.
        :txn: ovn northbound idl transaction.

        """
        meter = self._nb_idl.db_find_rows(
            "Meter", ("name", "=", meter_name)).execute(check_error=True)
        # The meters are created when a log object is created, not by default.
        # This condition avoids creating the meter if it wasn't there already.
        commands = []
        if from_reload and not meter:
            return

        burst_limit = cfg.CONF.network_log.burst_limit
        rate_limit = cfg.CONF.network_log.rate_limit
        if stateless:
            meter_name = meter_name + "_stateless"
            burst_limit = int(burst_limit / 2)
            rate_limit = int(rate_limit / 2)
        # The stateless meter is only created once the stateful meter was
        # successfully created.
        # The treatment of limits is not equal for stateful and stateless
        # traffic at a kernel level according to:
        # https://bugzilla.redhat.com/show_bug.cgi?id=2212952
        # The stateless meter is created to adjust this issue.
        meter = self._nb_idl.db_find_rows(
            "Meter", ("name", "=", meter_name)).execute(check_error=True)
        if meter:
            meter = meter[0]
            meter_band = self._nb_idl.lookup("Meter_Band",
                                             meter.bands[0].uuid, default=None)
            if meter_band:
                if all((meter.unit == "pktps",
                        meter.fair[0],
                        meter_band.rate == rate_limit,
                        meter_band.burst_size == burst_limit)):
                    # Meter (and its meter-band) unchanged: noop.
                    return
            # Re-create meter (and its meter-band) with the new attributes.
            # This is supposed to happen only if configuration changed, so
            # doing updates is an overkill: better to leverage the ovsdbapp
            # library to avoid the complexity.
            LOG.info("Deleting outdated log fair meter %s", meter_name)
            commands.append(self._nb_idl.meter_del(meter.uuid))
        # Create meter
        LOG.info("Creating network log fair meter %s", meter_name)
        commands.append(self._nb_idl.meter_add(
                        name=meter_name,
                        unit="pktps",
                        rate=rate_limit,
                        fair=True,
                        burst_size=burst_limit,
                        may_exist=False,
                        external_ids={ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                                      log_const.LOGGING_PLUGIN}))
        self._transaction(commands, txn=txn)

    def create_ovn_fair_meter(self, meter_name, from_reload=False, txn=None):
        self._create_ovn_fair_meter(meter_name, from_reload, txn)
        self._create_ovn_fair_meter(meter_name, from_reload, txn,
                                    stateless=True)
