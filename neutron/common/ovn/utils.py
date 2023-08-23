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
import inspect
import os
import random

import netaddr
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net
from neutron_lib.api import validators
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.utils import net as n_utils
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import netutils
from oslo_utils import strutils
from ovsdbapp.backend.ovs_idl import rowview
from ovsdbapp import constants as ovsdbapp_const
import tenacity

from neutron._i18n import _
from neutron.common.ovn import constants
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common import utils as common_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import models_v2
from neutron.objects import ports as ports_obj

LOG = log.getLogger(__name__)

CONF = cfg.CONF

DNS_RESOLVER_FILE = "/etc/resolv.conf"

AddrPairsDiff = collections.namedtuple(
    'AddrPairsDiff', ['added', 'removed', 'changed'])

PortExtraDHCPValidation = collections.namedtuple(
    'PortExtraDHCPValidation', ['failed', 'invalid_ipv4', 'invalid_ipv6'])
BPInfo = collections.namedtuple(
    'BPInfo', ['bp_param', 'vnic_type', 'capabilities'])


class OvsdbClientCommand(object):
    _CONNECTION = 0
    _PRIVATE_KEY = 1
    _CERTIFICATE = 2
    _CA_AUTHORITY = 3

    OVN_Northbound = "OVN_Northbound"
    OVN_Southbound = "OVN_Southbound"

    _db_settings = {
        OVN_Northbound: {
            _CONNECTION: ovn_conf.get_ovn_nb_connection,
            _PRIVATE_KEY: ovn_conf.get_ovn_nb_private_key,
            _CERTIFICATE: ovn_conf.get_ovn_nb_certificate,
            _CA_AUTHORITY: ovn_conf.get_ovn_nb_ca_cert,
        },
        OVN_Southbound: {
            _CONNECTION: ovn_conf.get_ovn_sb_connection,
            _PRIVATE_KEY: ovn_conf.get_ovn_sb_private_key,
            _CERTIFICATE: ovn_conf.get_ovn_sb_certificate,
            _CA_AUTHORITY: ovn_conf.get_ovn_sb_ca_cert,
        },
    }

    @classmethod
    def run(cls, command):
        """Run custom ovsdb protocol command.

        :param command: JSON object of ovsdb protocol command
        """
        try:
            db = command[0]
        except IndexError:
            raise KeyError(
                _("%s or %s schema must be specified in the command %s" % (
                    cls.OVN_Northbound, cls.OVN_Southbound, command)))

        if db not in (cls.OVN_Northbound, cls.OVN_Southbound):
            raise KeyError(
                _("%s or %s schema must be specified in the command %s" % (
                    cls.OVN_Northbound, cls.OVN_Southbound, command)))

        cmd = ['ovsdb-client',
               cls.COMMAND,
               cls._db_settings[db][cls._CONNECTION](),
               '--timeout',
               str(ovn_conf.get_ovn_ovsdb_timeout())]

        if cls._db_settings[db][cls._PRIVATE_KEY]():
            cmd += ['-p', cls._db_settings[db][cls._PRIVATE_KEY](),
                    '-c', cls._db_settings[db][cls._CERTIFICATE](),
                    '-C', cls._db_settings[db][cls._CA_AUTHORITY]()]

        cmd.append(jsonutils.dumps(command))

        return processutils.execute(
            *cmd,
            log_errors=processutils.LOG_FINAL_ERROR)


class OvsdbClientTransactCommand(OvsdbClientCommand):
    COMMAND = 'transact'


def ovn_name(id):
    # The name of the OVN entry will be neutron-<UUID>
    # This is due to the fact that the OVN application checks if the name
    # is a UUID. If so then there will be no matches.
    # We prefix the UUID to enable us to use the Neutron UUID when
    # updating, deleting etc.
    return "%s%s" % (constants.OVN_NAME_PREFIX, id)


def ovn_lrouter_port_name(id):
    # The name of the OVN lrouter port entry will be lrp-<UUID>
    # This is to distinguish with the name of the connected lswitch patch port,
    # which is named with neutron port uuid, so that OVS patch ports are
    # generated properly. The pairing patch port names will be:
    #   - patch-lrp-<UUID>-to-<UUID>
    #   - patch-<UUID>-to-lrp-<UUID>
    # lrp stands for Logical Router Port
    return constants.LRP_PREFIX + '%s' % id


def ovn_cr_lrouter_port_name(_id):
    # The name of the OVN chassisredirect lrouter port entry will be
    # cr-lrp-<UUID>
    return 'cr-lrp-%s' % _id


def ovn_provnet_port_name(network_id):
    # The name of OVN lswitch provider network port entry will be
    # provnet-<Network-UUID>. The port is created for network having
    # provider:physical_network attribute.
    return constants.OVN_PROVNET_PORT_NAME_PREFIX + '%s' % network_id


def ovn_vhu_sockpath(sock_dir, port_id):
    # Frame the socket path of a virtio socket
    return os.path.join(
        sock_dir,
        # this parameter will become the virtio port name,
        # so it should not exceed IFNAMSIZ(16).
        (const.VHOST_USER_DEVICE_PREFIX + port_id)[:14])


def ovn_addrset_name(sg_id, ip_version):
    # The name of the address set for the given security group id and ip
    # version. The format is:
    #   as-<ip version>-<security group uuid>
    # with all '-' replaced with '_'. This replacement is necessary
    # because OVN doesn't support '-' in an address set name.
    return ('as-%s-%s' % (ip_version, sg_id)).replace('-', '_')


def ovn_pg_addrset_name(sg_id, ip_version):
    # The name of the address set for the given security group id modelled as a
    # Port Group and ip version. The format is:
    #   pg-<security group uuid>-<ip version>
    # with all '-' replaced with '_'. This replacement is necessary
    # because OVN doesn't support '-' in an address set name.
    return ('pg-%s-%s' % (sg_id, ip_version)).replace('-', '_')


def ovn_port_group_name(sg_id):
    # The name of the port group for the given security group id.
    # The format is: pg-<security group uuid>.
    return ('pg-%s' % sg_id).replace('-', '_')


def is_network_device_port(port):
    return port.get('device_owner', '').startswith(
        const.DEVICE_OWNER_PREFIXES)


def _is_dhcp_disabled(dhcp_opt):
    return (dhcp_opt['opt_name'] == constants.DHCP_DISABLED_OPT and
            dhcp_opt.get('opt_value', '').lower() == 'true')


def validate_port_extra_dhcp_opts(port):
    """Validate port's extra DHCP options.

    :param port: A neutron port.
    :returns: A PortExtraDHCPValidation object.
    """
    # Get the right option mappings according to the port's vnic_type
    vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
    mapping = constants.SUPPORTED_DHCP_OPTS_MAPPING
    if vnic_type == portbindings.VNIC_BAREMETAL:
        mapping = constants.SUPPORTED_BM_DHCP_OPTS_MAPPING

    invalid = {const.IP_VERSION_4: [], const.IP_VERSION_6: []}
    failed = False
    for edo in port.get(edo_ext.EXTRADHCPOPTS, []):
        ip_version = edo['ip_version']
        opt_name = edo['opt_name']

        # If DHCP is disabled for this port via this special option,
        # always succeed the validation
        if _is_dhcp_disabled(edo):
            failed = False
            break

        if opt_name not in mapping[ip_version]:
            invalid[ip_version].append(opt_name)
            failed = True

    return PortExtraDHCPValidation(
        failed=failed,
        invalid_ipv4=invalid[const.IP_VERSION_4] if failed else [],
        invalid_ipv6=invalid[const.IP_VERSION_6] if failed else [])


def is_dhcp_option_quoted(opt_value):
    return opt_value.startswith('"') and opt_value.endswith('"')


def get_lsp_dhcp_opts(port, ip_version):
    # Get dhcp options from Neutron port, for setting DHCP_Options row
    # in OVN.
    lsp_dhcp_disabled = False
    lsp_dhcp_opts = {}
    vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
    is_baremetal = vnic_type == portbindings.VNIC_BAREMETAL

    if is_network_device_port(port):
        lsp_dhcp_disabled = True
    elif is_baremetal and ovn_conf.is_ovn_dhcp_disabled_for_baremetal():
        lsp_dhcp_disabled = True
    else:
        mapping = (constants.SUPPORTED_BM_DHCP_OPTS_MAPPING[ip_version]
                   if is_baremetal else
                   constants.SUPPORTED_DHCP_OPTS_MAPPING[ip_version])
        for edo in port.get(edo_ext.EXTRADHCPOPTS, []):
            if edo['ip_version'] != ip_version:
                continue

            if _is_dhcp_disabled(edo):
                # OVN native DHCP is disabled on this port
                lsp_dhcp_disabled = True
                # Make sure return value behavior not depends on the order and
                # content of the extra DHCP options for the port
                lsp_dhcp_opts.clear()
                break

            if edo['opt_name'] not in mapping:
                LOG.warning('The DHCP option %(opt_name)s on port %(port)s '
                            'is not suppported by OVN, ignoring it',
                            {'opt_name': edo['opt_name'], 'port': port['id']})
                continue

            opt = mapping[edo['opt_name']]
            if (opt in constants.OVN_STR_TYPE_DHCP_OPTS and
                    not is_dhcp_option_quoted(edo['opt_value'])):
                edo['opt_value'] = '"%s"' % edo['opt_value']
            lsp_dhcp_opts[opt] = edo['opt_value']

    return (lsp_dhcp_disabled, lsp_dhcp_opts)


def is_lsp_trusted(port):
    return n_utils.is_port_trusted(port) if port.get('device_owner') else False


def is_lsp_ignored(port):
    # Since the floating IP port is not bound to any chassis, packets from vm
    # destined to floating IP will be dropped. To overcome this, we do not
    # create/update floating IP port in OVN.
    return port.get('device_owner') in [const.DEVICE_OWNER_FLOATINGIP]


def get_lsp_security_groups(port, skip_trusted_port=True):
    # In other agent link OVS, skipping trusted port is processed in security
    # groups RPC.  We haven't that step, so we do it here.
    return [] if (skip_trusted_port and is_lsp_trusted(port)
                  ) else port.get('security_groups', [])


def is_snat_enabled(router):
    return router.get(l3.EXTERNAL_GW_INFO, {}).get('enable_snat', True)


def is_port_security_enabled(port):
    return port.get(psec.PORTSECURITY)


def is_security_groups_enabled(port):
    return port.get(constants.PORT_SECURITYGROUPS)


def validate_and_get_data_from_binding_profile(port):
    """Validate the port binding profile

    :param port: (dict) Neutron port dictionary.
    :returns: (namedtuple BPInfo: dict, string, list) a tuple with the
              dictionary of the port profile, the VNIC type and a list of port
              capabilities.
    """
    if (constants.OVN_PORT_BINDING_PROFILE not in port or
            not validators.is_attr_set(
                port[constants.OVN_PORT_BINDING_PROFILE])):
        BPInfo({}, None, [])
    param_set = {}
    param_dict = {}
    vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)

    # A port's capabilities is listed as part of the binding profile, but we
    # treat it separately and do not want it to be included in the generic
    # validation.
    binding_profile = copy.deepcopy(port[constants.OVN_PORT_BINDING_PROFILE])
    capabilities = binding_profile.pop(constants.PORT_CAP_PARAM, [])
    if not isinstance(capabilities, list):
        msg = _('Invalid binding:profile. %s must be of type list.'
                ) % constants.PORT_CAP_PARAM
        raise n_exc.InvalidInput(error_message=msg)

    # Note that only the keys mentioned in each parameter set, as defined in
    # constants.OVN_PORT_BINDING_PROFILE_PARAMS, will be evaluated.
    #
    # Any surplus keys provided by Nova will be ignored and pruned from the
    # Dict returned by this function.
    for pbp_param_set in constants.OVN_PORT_BINDING_PROFILE_PARAMS:
        if pbp_param_set.vnic_type:
            if pbp_param_set.vnic_type != vnic_type:
                continue
            if capabilities and pbp_param_set.capability not in capabilities:
                continue
        param_set = pbp_param_set.param_set
        param_keys = param_set.keys()
        for param_key in param_keys:
            try:
                param_dict[param_key] = binding_profile[param_key]
            except KeyError:
                pass
        if len(param_dict) == 0:
            continue
        if param_keys - binding_profile.keys():
            msg = _('Invalid binding:profile. %s are all '
                    'required.') % param_keys
            raise n_exc.InvalidInput(error_message=msg)
        break

    if not param_dict:
        return BPInfo({}, vnic_type, capabilities)

    # With this example param_set:
    #
    # param_set = {
    #     'do_not_check_this_key': None,
    #     'pci_slot': [str],
    #     'physical_network': [str, type(None)]
    # }
    #
    # We confirm that each binding_profile key is of one of the listed types,
    # allowing validation of polymorphic entries.
    #
    # 'physical_network' is polymorphic because:  When a VNIC_REMOTE_MANAGED or
    # VNIC_DIRECT with PORT_CAP_SWITCHDEV capability port is attached to a
    # project network backed by an overlay (tunneled) network the value will be
    # 'None'.  For the case of ports attached to a project network backed by
    # VLAN the value will be of type ``str``.  This comes from Nova and is
    # provided in the ``physical_network`` tag in the Nova PCI Passthrough
    # configuration.
    #
    # In the above example the type of the value behind 'do_not_check_this_key'
    # will not be checked, 'pci_slot' must be ``str``, 'physical_network  must
    # be either ``str`` or ``NoneType``.
    for param_key, param_types in param_set.items():
        if param_types is None:
            continue
        param_value = param_dict[param_key]
        for param_type in param_types:
            if isinstance(param_value, param_type):
                break
        else:
            msg = _('Invalid binding:profile. %(key)s %(value)s '
                    'value invalid type') % {'key': param_key,
                                             'value': param_value}
            raise n_exc.InvalidInput(error_message=msg)

    # Make sure we can successfully look up the port indicated by
    # parent_name.  Just let it raise the right exception if there is a
    # problem.
    if 'parent_name' in param_set:
        plugin = directory.get_plugin()
        plugin.get_port(n_context.get_admin_context(),
                        param_dict['parent_name'])

    if 'tag' in param_set:
        tag = int(param_dict['tag'])
        if tag < 0 or tag > 4095:
            msg = _('Invalid binding:profile. tag "%s" must be '
                    'an integer between 0 and 4095, inclusive') % tag
            raise n_exc.InvalidInput(error_message=msg)

    return BPInfo(param_dict, vnic_type, capabilities)


def is_dhcp_options_ignored(subnet):
    # Don't insert DHCP_Options entry for v6 subnet with 'SLAAC' as
    # 'ipv6_address_mode', since DHCPv6 shouldn't work for this mode.
    return (subnet['ip_version'] == const.IP_VERSION_6 and
            subnet.get('ipv6_address_mode') == const.IPV6_SLAAC)


def get_ovn_ipv6_address_mode(address_mode):
    return constants.OVN_IPV6_ADDRESS_MODES[address_mode]


def get_revision_number(resource, resource_type):
    """Get the resource's revision number based on its type."""
    if resource_type in (constants.TYPE_NETWORKS,
                         constants.TYPE_PORTS,
                         constants.TYPE_SECURITY_GROUP_RULES,
                         constants.TYPE_ROUTERS,
                         constants.TYPE_ROUTER_PORTS,
                         constants.TYPE_SECURITY_GROUPS,
                         constants.TYPE_FLOATINGIPS, constants.TYPE_SUBNETS):
        return resource['revision_number']
    else:
        raise ovn_exc.UnknownResourceType(resource_type=resource_type)


def remove_macs_from_lsp_addresses(addresses):
    """Remove the mac addresses from the Logical_Switch_Port addresses column.

    :param addresses: The list of addresses from the Logical_Switch_Port.
        Example: ["80:fa:5b:06:72:b7 158.36.44.22",
                  "ff:ff:ff:ff:ff:ff 10.0.0.2"]
    :returns: A list of IP addresses (v4 and v6)
    """
    ip_list = []
    for addr in addresses:
        ip_list.extend([x for x in addr.split() if
                        (netutils.is_valid_ipv4(x) or
                         netutils.is_valid_ipv6(x))])
    return ip_list


def get_allowed_address_pairs_ip_addresses(port):
    """Return a list of IP addresses from port's allowed_address_pairs.

    :param port: A neutron port
    :returns: A list of IP addresses (v4 and v6)
    """
    return [x['ip_address'] for x in port.get('allowed_address_pairs', [])
            if 'ip_address' in x]


def get_allowed_address_pairs_ip_addresses_from_ovn_port(ovn_port):
    """Return a list of IP addresses from ovn port.

    Return a list of IP addresses equivalent of Neutron's port
    allowed_address_pairs column using the data in the OVN port.

    :param ovn_port: A OVN port
    :returns: A list of IP addresses (v4 and v6)
    """
    addresses = remove_macs_from_lsp_addresses(ovn_port.addresses)
    port_security = remove_macs_from_lsp_addresses(ovn_port.port_security)
    return [x for x in port_security if x not in addresses]


def get_ovn_port_security_groups(ovn_port, skip_trusted_port=True):
    info = {'security_groups': ovn_port.external_ids.get(
                constants.OVN_SG_IDS_EXT_ID_KEY, '').split(),
            'device_owner': ovn_port.external_ids.get(
                constants.OVN_DEVICE_OWNER_EXT_ID_KEY, '')}
    return get_lsp_security_groups(info, skip_trusted_port=skip_trusted_port)


def get_ovn_port_addresses(ovn_port):
    addresses = remove_macs_from_lsp_addresses(ovn_port.addresses)
    port_security = remove_macs_from_lsp_addresses(ovn_port.port_security)
    return list(set(addresses + port_security))


def get_virtual_port_parents(nb_idl, virtual_ip, network_id, port_id):
    ls = nb_idl.ls_get(ovn_name(network_id)).execute(check_error=True)
    return [lsp.name for lsp in ls.ports
            if lsp.name != port_id and
            virtual_ip in get_ovn_port_addresses(lsp)]


def sort_ips_by_version(addresses):
    ip_map = {'ip4': [], 'ip6': []}
    for addr in addresses:
        ip_version = netaddr.IPNetwork(addr).version
        ip_map['ip%d' % ip_version].append(addr)
    return ip_map


def is_lsp_router_port(port):
    return port.get('device_owner') in const.ROUTER_PORT_OWNERS


def get_lrouter_ext_gw_static_route(ovn_router):
    return [route for route in getattr(ovn_router, 'static_routes', []) if
            strutils.bool_from_string(getattr(
                route, 'external_ids', {}).get(
                    constants.OVN_ROUTER_IS_EXT_GW, 'false'))]


def get_lrouter_snats(ovn_router):
    return [n for n in getattr(ovn_router, 'nat', []) if n.type == 'snat']


def get_lrouter_non_gw_routes(ovn_router):
    routes = []
    for route in getattr(ovn_router, 'static_routes', []):
        external_ids = getattr(route, 'external_ids', {})
        if strutils.bool_from_string(
                external_ids.get(constants.OVN_ROUTER_IS_EXT_GW, 'false')):
            continue

        routes.append({'destination': route.ip_prefix,
                       'nexthop': route.nexthop})
    return routes


def is_ovn_l3(l3_plugin):
    return hasattr(l3_plugin, '_ovn_client_inst')


def get_system_dns_resolvers(resolver_file=DNS_RESOLVER_FILE):
    resolvers = []
    if not os.path.exists(resolver_file):
        return resolvers

    with open(resolver_file, 'r') as rconf:
        for line in rconf.readlines():
            if not line.startswith('nameserver'):
                continue

            line = line.split('nameserver')[1].strip()
            valid_ip = (netutils.is_valid_ipv4(line, strict=True) or
                        netutils.is_valid_ipv6(line))
            if valid_ip:
                resolvers.append(line)

    return resolvers


def get_dhcp_dns_servers(subnet, ip_version=const.IP_VERSION_4):
    """Retrieve the DHCP option DNS servers

    The DHCP should not announce any DNS resolver at all on the subnet if any
    configured DNS server is "0.0.0.0" (IPv4) or "::" (IPv6).
    https://docs.openstack.org/neutron/latest/admin/config-dns-res.html
    """
    def filter_ips(ips, ip_version=const.IP_VERSION_4):
        return [ip for ip in ips
                if netaddr.IPAddress(ip).version == ip_version]

    dns_servers = (subnet.get('dns_nameservers') or
                   filter_ips(ovn_conf.get_dns_servers(), ip_version) or
                   filter_ips(get_system_dns_resolvers(), ip_version))

    if common_utils.is_dns_servers_any_address(dns_servers, ip_version):
        return []

    return dns_servers


def get_port_subnet_ids(port):
    fixed_ips = list(port['fixed_ips'])
    return [f['subnet_id'] for f in fixed_ips]


def get_method_class(method):
    if not inspect.ismethod(method):
        return
    return method.__self__.__class__


def ovn_metadata_name(id_):
    """Return the OVN metadata name based on an id."""
    return 'metadata-%s' % id_


def is_ovn_metadata_port(port):
    return (port['device_owner'] == const.DEVICE_OWNER_DISTRIBUTED and
            port['device_id'].startswith('ovnmeta'))


def is_gateway_chassis_invalid(chassis_name, gw_chassis,
                               physnet, chassis_physnets,
                               az_hints, chassis_with_azs):
    """Check if gateway chassis is invalid

    @param    chassis_name: gateway chassis name
    @type     chassis_name: string
    @param    gw_chassis: List of gateway chassis in the system
    @type     gw_chassis: []
    @param    physnet: physical network associated to chassis_name
    @type     physnet: string
    @param    chassis_physnets: Dictionary linking chassis with their physnets
    @type     chassis_physnets: {}
    @param   az_hints: available zone hints associated to chassis_name
    @type     az_hints: []
    @param    chassis_with_azs: Dictionary linking chassis with their azs
    @type     chassis_with_azs: {}
    @return   Boolean
    """

    if chassis_name == constants.OVN_GATEWAY_INVALID_CHASSIS:
        return True
    elif chassis_name not in chassis_physnets:
        return True
    elif physnet and physnet not in chassis_physnets.get(chassis_name):
        return True
    elif gw_chassis and chassis_name not in gw_chassis:
        return True
    elif az_hints and not set(az_hints) & set(chassis_with_azs.get(
            chassis_name, [])):
        return True
    return False


def is_provider_network(network):
    return network.get(provider_net.PHYSICAL_NETWORK, False)


def is_external_network(network):
    return network.get(external_net.EXTERNAL, False)


def compute_address_pairs_diff(ovn_port, neutron_port):
    """Compute the differences in the allowed_address_pairs field."""
    ovn_ap = get_allowed_address_pairs_ip_addresses_from_ovn_port(
        ovn_port)
    neutron_ap = get_allowed_address_pairs_ip_addresses(neutron_port)
    added = set(neutron_ap) - set(ovn_ap)
    removed = set(ovn_ap) - set(neutron_ap)
    return AddrPairsDiff(added, removed, changed=any(added or removed))


def get_ovn_cms_options(chassis):
    """Return the list of CMS options in a Chassis."""
    return [opt.strip() for opt in get_ovn_chassis_other_config(chassis).get(
        constants.OVN_CMS_OPTIONS, '').split(',')]


def is_gateway_chassis(chassis):
    """Check if the given chassis is a gateway chassis"""
    return constants.CMS_OPT_CHASSIS_AS_GW in get_ovn_cms_options(chassis)


def get_port_capabilities(port):
    """Return a list of port's capabilities"""
    return port.get(portbindings.PROFILE, {}).get(constants.PORT_CAP_PARAM, [])


def get_port_id_from_gwc_row(row):
    """Return a port_id from gwc row

    The Gateway_Chassis row stores router port_id in
    the row name attribute:

    <prefix>-<port_id>_<chassis_id>

    :param row: A Gateway_Chassis table row.
    :returns: String containing router port_id.
    """
    return constants.RE_PORT_FROM_GWC.search(row.name).group(2)


def get_chassis_availability_zones(chassis):
    """Return a list of availability zones from a given OVN Chassis."""
    azs = set()
    if not chassis:
        return azs

    opt_key = constants.CMS_OPT_AVAILABILITY_ZONES + '='
    for opt in get_ovn_cms_options(chassis):
        if not opt.startswith(opt_key):
            continue
        values = opt.split('=')[1]
        azs = {az.strip() for az in values.split(':') if az.strip()}
        break
    return azs


def get_chassis_in_azs(chassis_list, az_list):
    """Return a set of Chassis that belongs to the AZs.

    Given a list of Chassis and a list of availability zones (AZs),
    return a set of Chassis that belongs to one or more AZs.

    :param chassis_list: A list of Chassis objects
    :param az_list: A list of availability zones
    :returns: A set of Chassis names
    """
    chassis = set()
    for ch in chassis_list:
        chassis_azs = get_chassis_availability_zones(ch)
        if chassis_azs.intersection(az_list):
            chassis.add(ch.name)
    return chassis


def get_gateway_chassis_without_azs(chassis_list):
    """Return a set of Chassis that does not belong to any AZs.

    Filter a list of Chassis and return only the Chassis that does not
    belong to any availability zones.

    :param chassis_list: A list of Chassis objects
    :returns: A set of Chassis names
    """
    return {ch.name for ch in chassis_list if is_gateway_chassis(ch) and not
            get_chassis_availability_zones(ch)}


def parse_ovn_lb_port_forwarding(ovn_rtr_lb_pfs):
    """Return a dictionary compatible with port forwarding from OVN lb."""
    result = {}
    for ovn_lb in ovn_rtr_lb_pfs:
        ext_ids = ovn_lb.external_ids
        fip_id = ext_ids.get(constants.OVN_FIP_EXT_ID_KEY)
        protocol = (ovn_lb.protocol[0]
                    if ovn_lb.protocol else ovsdbapp_const.PROTO_TCP)
        fip_dict = result.get(fip_id, {})
        fip_dict_proto = fip_dict.get(protocol, set())
        ovn_vips = ovn_lb.vips
        for vip, ips in ovn_vips.items():
            for ip in ips.split(','):
                fip_dict_proto.add("{} {}".format(vip, ip))
        fip_dict[protocol] = fip_dict_proto
        result[fip_id] = fip_dict
    return result


def get_network_name_from_datapath(datapath):
    return datapath.external_ids['name'].replace('neutron-', '')


def is_port_external(port):
    # This port is represented in OVN DB as lsp.type=external
    capabilities = []
    vnic_type = portbindings.VNIC_NORMAL

    if isinstance(port, dict):
        capabilities = get_port_capabilities(port)
        vnic_type = port.get(portbindings.VNIC_TYPE,
                             portbindings.VNIC_NORMAL)
    else:
        if isinstance(port, models_v2.Port):
            bindings = port.port_bindings
        elif isinstance(port, ports_obj.Port):
            bindings = port.bindings
        else:  # What else could be "port"?
            bindings = []

        if bindings:
            profile = bindings[0].get('profile')
            if profile:
                # DB object, not OVO, stores the dict in JSON.
                profile = (jsonutils.loads(profile) if isinstance(profile, str)
                           else profile)
                capabilities = profile.get(constants.PORT_CAP_PARAM, [])
            vnic_type = bindings[0].get('vnic_type', portbindings.VNIC_NORMAL)

    return (vnic_type in constants.EXTERNAL_PORT_TYPES and
            constants.PORT_CAP_SWITCHDEV not in capabilities)


def retry(max_=None):
    def inner(func):
        def wrapper(*args, **kwargs):
            local_max = max_ or ovn_conf.get_ovn_ovsdb_retry_max_interval()
            return tenacity.retry(
                wait=tenacity.wait_exponential(max=local_max),
                reraise=True)(func)(*args, **kwargs)
        return wrapper
    return inner


def create_neutron_pg_drop():
    """Create neutron_pg_drop Port Group.

    It uses ovsdb-client to send to server transact command using ovsdb
    protocol that checks if the neutron_pg_drop row exists. If it exists
    it times out immediatelly. If it doesn't exist then it creates the
    Port_Group and default ACLs to drop all ingress and egress traffic.
    """
    command = [
        "OVN_Northbound", {
            "op": "wait",
            "timeout": 0,
            "table": "Port_Group",
            "where": [
                ["name", "==", constants.OVN_DROP_PORT_GROUP_NAME]
            ],
            "until": "==",
            "rows": []
        }, {
            "op": "insert",
            "table": "ACL",
            "row": {
                "action": "drop",
                "direction": "to-lport",
                "match": "outport == @neutron_pg_drop && ip",
                "priority": 1001
            },
            "uuid-name": "droptoport"
        }, {
            "op": "insert",
            "table": "ACL",
            "row": {
                "action": "drop",
                "direction": "from-lport",
                "match": "inport == @neutron_pg_drop && ip",
                "priority": 1001
            },
            "uuid-name": "dropfromport"
        }, {
            "op": "insert",
            "table": "Port_Group",
            "row": {
                "name": constants.OVN_DROP_PORT_GROUP_NAME,
                "acls": ["set", [
                    ["named-uuid", "droptoport"],
                    ["named-uuid", "dropfromport"]
                ]]
            }
        }]

    OvsdbClientTransactCommand.run(command)


def get_ovn_chassis_other_config(chassis):
    # NOTE(ralonsoh): LP#1990229 to be removed when min OVN version is 22.09
    try:
        return chassis.other_config
    except AttributeError:
        return chassis.external_ids


def get_subnets_address_scopes(context, subnets, fixed_ips, ml2_plugin):
    """Returns the IPv4 and IPv6 address scopes of several subnets.

    The subnets hosted on the same network must be allocated from the same
    subnet pool (from ``NetworkSubnetPoolAffinityError`` exception). That
    applies per IP version (it means it is possible to have two subnet pools,
    one for IPv4 and one for IPv6).

    :param context: neutron api request context
    :param subnets: (list of dict) subnet dictionaries
    :param fixed_ips: (list of dict) fixed IPs of several subnets (usually
                      belonging to a network but not mandatory)
    :param ml2_plugin: (``Ml2Plugin``) ML2 plugin instance
    :return: (tuple of 2 strings) IPv4 and IPv6 address scope IDs
    """
    address4_scope_id, address6_scope_id = '', ''
    if not subnets:
        return address4_scope_id, address6_scope_id

    subnets_by_id = {subnet['id']: subnet for subnet in subnets}
    for fixed_ip in fixed_ips:
        subnet_id = fixed_ip.get('subnet_id')
        subnet = subnets_by_id.get(subnet_id)
        if not subnet or not subnet['subnetpool_id']:
            continue

        try:
            subnet_pool = ml2_plugin.get_subnetpool(context,
                                                    id=subnet['subnetpool_id'])
            if subnet_pool['address_scope_id']:
                if subnet_pool['ip_version'] == const.IP_VERSION_4:
                    address4_scope_id = subnet_pool['address_scope_id']
                else:
                    address6_scope_id = subnet_pool['address_scope_id']
        except n_exc.SubnetPoolNotFound:
            # swallow the exception and just continue if the
            # lookup failed
            pass

    return address4_scope_id, address6_scope_id


def sync_ha_chassis_group(context, network_id, nb_idl, sb_idl, txn):
    """Return the UUID of the HA Chassis Group or the HA Chassis Group cmd.

    Given the Neutron Network ID, this method will return (or create
    and then return) the appropriate HA Chassis Group the external
    port (in that network) needs to be associated with.

    :param context: Neutron API context.
    :param network_id: The Neutron network ID.
    :param nb_idl: OVN NB IDL
    :param sb_idl: OVN SB IDL
    :param txn: The ovsdbapp transaction object.
    :returns: The HA Chassis Group UUID or the HA Chassis Group command object.
    """
    plugin = directory.get_plugin()
    az_hints = common_utils.get_az_hints(
        plugin.get_network(context, network_id))

    ha_ch_grp_name = ovn_name(network_id)
    ext_ids = {constants.OVN_AZ_HINTS_EXT_ID_KEY: ','.join(az_hints)}
    hcg_cmd = txn.add(nb_idl.ha_chassis_group_add(
        ha_ch_grp_name, may_exist=True, external_ids=ext_ids))

    if isinstance(hcg_cmd.result, rowview.RowView):
        # The HA chassis group existed before this transaction.
        ha_ch_grp = hcg_cmd.result
    else:
        # The HA chassis group is being created in this transaction.
        ha_ch_grp = None

    # Get the chassis belonging to the AZ hints
    ch_list = sb_idl.get_gateway_chassis_from_cms_options(name_only=False)
    if not az_hints:
        az_chassis = get_gateway_chassis_without_azs(ch_list)
    else:
        az_chassis = get_chassis_in_azs(ch_list, az_hints)

    priority = constants.HA_CHASSIS_GROUP_HIGHEST_PRIORITY
    if ha_ch_grp:
        # Remove any chassis that no longer belongs to the AZ hints
        all_ch = {ch.chassis_name for ch in ha_ch_grp.ha_chassis}
        ch_to_del = all_ch - az_chassis
        for ch in ch_to_del:
            txn.add(nb_idl.ha_chassis_group_del_chassis(
                ha_ch_grp_name, ch, if_exists=True))

        # Find the highest priority chassis in the HA Chassis Group. If
        # it exists and still belongs to the same AZ, keep it as the
        # highest priority in the group to avoid ports already bond to it
        # from moving to another chassis.
        high_prio_ch = max(ha_ch_grp.ha_chassis, key=lambda x: x.priority,
                           default=None)
        priority = constants.HA_CHASSIS_GROUP_HIGHEST_PRIORITY
        if high_prio_ch and high_prio_ch.chassis_name in az_chassis:
            txn.add(nb_idl.ha_chassis_group_add_chassis(
                ha_ch_grp_name, high_prio_ch.chassis_name,
                priority=priority))
            az_chassis.remove(high_prio_ch.chassis_name)
            priority -= 1

    # Randomize the order so that networks belonging to the same
    # availability zones do not necessarily end up with the same
    # Chassis as the highest priority one.
    for ch in random.sample(list(az_chassis), len(az_chassis)):
        txn.add(nb_idl.ha_chassis_group_add_chassis(
            hcg_cmd, ch, priority=priority))
        priority -= 1

    # Return the existing register UUID or the HA chassis group creation
    # command (see ovsdbapp ``HAChassisGroupAddChassisCommand`` class).
    return ha_ch_grp.uuid if ha_ch_grp else hcg_cmd


def get_port_type_virtual_and_parents(subnets, fixed_ips, network_id, port_id,
                                      nb_idl):
    """Returns if a port is type virtual and its corresponding parents.

    :param subnets: (list of dict) subnet dictionaries
    :param fixed_ips: (list of dict) fixed IPs of several subnets (usually
                      belonging to a network but not mandatory)
    :param network_id: (string) network ID
    :param port_id: (string) port ID
    :param nb_idl: (``OvsdbNbOvnIdl``) OVN Northbound IDL
    :return: (tuple, three strings) (1) the virtual type ('' if not virtual),
             (2) the virtual IP address and (3) the virtual parents
    """
    port_type, virtual_ip, virtual_parents = '', None, None
    if not subnets:
        return port_type, virtual_ip, virtual_parents

    subnets_by_id = {subnet['id'] for subnet in subnets}
    for fixed_ip in fixed_ips:
        if fixed_ip.get('subnet_id') not in subnets_by_id:
            continue

        # Check if the port being created is a virtual port
        parents = get_virtual_port_parents(
            nb_idl, fixed_ip['ip_address'], network_id, port_id)
        if not parents:
            continue

        port_type = constants.LSP_TYPE_VIRTUAL
        virtual_ip = fixed_ip['ip_address']
        virtual_parents = ','.join(parents)
        break

    return port_type, virtual_ip, virtual_parents


def determine_bind_host(sb_idl, port, port_context=None):
    """Determine which host the port should be bound to.

    Traditionally it has been Nova's responsibility to create Virtual
    Interfaces (VIFs) as part of instance life cycle, and subsequently
    manage plug/unplug operations on the Open vSwitch integration bridge.
    For the traditional topology the bind host will be the same as the
    hypervisor hosting the instance.

    With the advent of SmartNIC DPUs which are connected to multiple
    distinct CPUs we can have a topology where the instance runs on one
    host and Open vSwitch and OVN runs on a different host, the SmartNIC
    DPU control plane CPU.  In the SmartNIC DPU topology the bind host will
    be different than the hypervisor host.

    This helper accepts both a port Dict and optionally a PortContext
    instance so that it can be used both before and after a port is bound.

    :param sb_idl: OVN Southbound IDL
    :type sb_idl: ``OvsdbSbOvnIdl``
    :param port: Port Dictionary
    :type port: Dict[str,any]
    :param port_context: PortContext instance describing the port
    :type port_context: api.PortContext
    :returns: FQDN or Hostname to bind port to.
    :rtype: str
    :raises: n_exc.InvalidInput, RuntimeError
    """
    # Note that we use port_context.host below when called from bind_port
    port = port_context.current if port_context else port
    vnic_type = port.get(portbindings.VNIC_TYPE, portbindings.VNIC_NORMAL)
    if vnic_type != portbindings.VNIC_REMOTE_MANAGED:
        # The ``PortContext`` ``host`` property contains handling of
        # special cases.
        return port_context.host if port_context else port.get(
            portbindings.HOST_ID, '')

    bp_info = validate_and_get_data_from_binding_profile(port)
    if constants.VIF_DETAILS_CARD_SERIAL_NUMBER in bp_info.bp_param:
        return sb_idl.get_chassis_by_card_serial_from_cms_options(
            bp_info.bp_param[
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER]).hostname
    return ''


def validate_port_binding_and_virtual_port(
        port_context, nb_idl, ml2_plugin, port, original_port):
    """If the port is type=virtual and it is bound, raise BadRequest"""
    # If the port receives an update of the device ID and the binding profile
    # host ID fields, at the same time, this is because Nova is trying to bind
    # the port to a VM (device ID) in a host (host ID).
    if not (port['device_id'] != original_port['device_id'] and
            port[portbindings.HOST_ID] != original_port[portbindings.HOST_ID]):
        return

    fixed_ips = port.get('fixed_ips', [])
    subnet_ids = set([fixed_ip['subnet_id'] for fixed_ip in fixed_ips
                      if 'subnet_id' in fixed_ip])
    if not subnet_ids:
        # If the port has no fixed_ips/subnets, it cannot be virtual.
        return

    subnets = ml2_plugin.get_subnets(port_context.plugin_context,
                                     filters={'id': list(subnet_ids)})
    port_type, _, _ = get_port_type_virtual_and_parents(
        subnets, fixed_ips, port['network_id'], port['id'], nb_idl)
    if port_type == constants.LSP_TYPE_VIRTUAL:
        raise n_exc.BadRequest(
            resource='port',
            msg='A virtual logical switch port cannot be bound to a host')


def get_requested_chassis(requested_chassis):
    """Returns a list with the items in the LSP.options:requested-chassis"""
    if isinstance(requested_chassis, str):
        return requested_chassis.split(',')
    return []
