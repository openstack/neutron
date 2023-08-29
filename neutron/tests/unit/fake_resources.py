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

import collections
import copy
import sys
from unittest import mock

from neutron_lib.api.definitions import l3
from neutron_lib import constants as n_const
from neutron_lib.utils import net
from oslo_utils import uuidutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils


class FakeOvsdbNbOvnIdl(object):

    def __init__(self, **kwargs):
        self.lswitch_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.lsp_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.lrouter_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.lrouter_static_route_table = \
            FakeOvsdbTable.create_one_ovsdb_table()
        self.lrp_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.addrset_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.acl_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.dhcp_options_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.nat_table = FakeOvsdbTable.create_one_ovsdb_table()
        self.port_group_table = FakeOvsdbTable.create_one_ovsdb_table()
        self._tables = {}
        self._tables['Logical_Switch'] = self.lswitch_table
        self._tables['Logical_Switch_Port'] = self.lsp_table
        self._tables['Logical_Router'] = self.lrouter_table
        self._tables['Logical_Router_Port'] = self.lrp_table
        self._tables['Logical_Router_Static_Route'] = \
            self.lrouter_static_route_table
        self._tables['ACL'] = self.acl_table
        self._tables['Address_Set'] = self.addrset_table
        self._tables['DHCP_Options'] = self.dhcp_options_table
        self._tables['NAT'] = self.nat_table
        self._tables['Port_Group'] = self.port_group_table
        self.transaction = mock.MagicMock()
        self.create_transaction = mock.MagicMock()
        self.ls_add = mock.Mock()
        self.ls_del = mock.Mock()
        self.create_lswitch_port = mock.Mock()
        self.set_lswitch_port = mock.Mock()
        self.delete_lswitch_port = mock.Mock()
        self.get_acls_for_lswitches = mock.Mock()
        self.create_lrouter = mock.Mock()
        self.lrp_del = mock.Mock()
        self.lrp_set_options = mock.Mock()
        self.update_lrouter = mock.Mock()
        self.delete_lrouter = mock.Mock()
        self.add_lrouter_port = mock.Mock()
        self.update_lrouter_port = mock.Mock()
        self.delete_lrouter_port = mock.Mock()
        self.set_lrouter_port_in_lswitch_port = mock.Mock()
        self.add_acl = mock.Mock()
        self.delete_acl = mock.Mock()
        self.update_acls = mock.Mock()
        self.idl = mock.Mock()
        self.add_static_route = mock.Mock()
        self.delete_static_route = mock.Mock()
        self.get_all_chassis_gateway_bindings = mock.Mock()
        self.get_chassis_gateways = mock.Mock()
        self.get_gateway_chassis_binding = mock.Mock()
        self.get_gateway_chassis_az_hints = mock.Mock()
        self.get_gateway_chassis_az_hints.return_value = []
        self.get_unhosted_gateways = mock.Mock()
        self.add_dhcp_options = mock.Mock()
        self.delete_dhcp_options = mock.Mock()
        self.get_subnet_dhcp_options = mock.Mock()
        self.get_subnet_dhcp_options.return_value = {
            'subnet': None, 'ports': []}
        self.get_subnets_dhcp_options = mock.Mock()
        self.get_subnets_dhcp_options.return_value = []
        self.get_all_dhcp_options = mock.Mock()
        self.get_router_port_options = mock.MagicMock()
        self.get_router_port_options.return_value = {}
        self.add_nat_rule_in_lrouter = mock.Mock()
        self.delete_nat_rule_in_lrouter = mock.Mock()
        self.get_lrouter_nat_rules = mock.Mock()
        self.get_lrouter_nat_rules.return_value = []
        self.set_nat_rule_in_lrouter = mock.Mock()
        self.check_for_row_by_value_and_retry = mock.Mock()
        self.get_parent_port = mock.Mock()
        self.get_parent_port.return_value = []
        self.dns_add = mock.Mock()
        self.get_lswitch = mock.Mock()
        self.fake_ls_row = FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ports': []})
        fake_lsp_row = FakeOvsdbRow.create_one_ovsdb_row()
        self.get_lswitch.return_value = self.fake_ls_row
        self.get_lswitch_port = mock.Mock()
        self.get_lswitch_port.return_value = fake_lsp_row
        self.get_ls_and_dns_record = mock.Mock()
        self.get_ls_and_dns_record.return_value = (self.fake_ls_row, None)
        self.ls_set_dns_records = mock.Mock()
        self.get_floatingip = mock.Mock()
        self.get_floatingip.return_value = None
        self.check_revision_number = mock.Mock()
        self.lookup = mock.MagicMock()
        # TODO(lucasagomes): The get_floatingip_by_ips() method is part
        # of a backwards compatibility layer for the Pike -> Queens release,
        # remove it in the Rocky release.
        self.get_floatingip_by_ips = mock.Mock()
        self.get_floatingip_by_ips.return_value = None
        self.get_router_floatingip_lbs = mock.Mock()
        self.get_router_floatingip_lbs.return_value = []
        self.is_col_present = mock.Mock()
        self.is_col_present.return_value = False
        self.is_col_supports_value = mock.Mock()
        self.is_col_supports_value.return_value = False
        self.get_lrouter = mock.Mock()
        self.get_lrouter.return_value = None
        self.delete_lrouter_ext_gw = mock.Mock()
        self.delete_lrouter_ext_gw.return_value = None
        self.pg_acl_add = mock.Mock()
        self.pg_acl_del = mock.Mock()
        self.pg_del = mock.Mock()
        self.pg_add = mock.Mock()
        self.get_port_group = mock.Mock()
        self.pg_add_ports = mock.Mock()
        self.pg_del_ports = mock.Mock()
        self.lsp_get_up = mock.Mock()
        self.nb_global = mock.Mock()
        self.nb_global.options.get.return_value = '100000'
        self.db_list_rows = mock.Mock()
        self.lsp_list = mock.MagicMock()
        self.db_find = mock.Mock()
        self.db_find_rows = mock.Mock()
        self.db_set = mock.Mock()
        self.db_clear = mock.Mock()
        self.db_remove = mock.Mock()
        self.set_lswitch_port_to_virtual_type = mock.Mock()
        self.unset_lswitch_port_to_virtual_type = mock.Mock()
        self.update_lb_external_ids = mock.Mock()
        self.lb_add = mock.Mock()
        self.lb_del = mock.Mock()
        self.lr_lb_add = mock.Mock()
        self.ls_get = mock.Mock()
        self.check_liveness = mock.Mock()
        self.ha_chassis_group_get = mock.Mock()
        self.qos_del = mock.Mock()
        self.qos_del_ext_ids = mock.Mock()
        self.meter_add = mock.Mock()
        self.meter_del = mock.Mock()
        self.ha_chassis_group_add = mock.Mock()
        self.ha_chassis_group_del = mock.Mock()
        self.ha_chassis_group_add_chassis = mock.Mock()
        self.ha_chassis_group_del_chassis = mock.Mock()
        self.lrp_get = mock.Mock()
        self.get_schema_version = mock.Mock(return_value='3.6.0')


class FakeOvsdbSbOvnIdl(object):

    def __init__(self, **kwargs):
        self.chassis_exists = mock.Mock()
        self.chassis_exists.return_value = True
        self.get_chassis_hostname_and_physnets = mock.Mock()
        self.get_chassis_hostname_and_physnets.return_value = {}
        self.get_chassis_and_azs = mock.Mock()
        self.get_chassis_and_azs.return_value = {}
        self.get_all_chassis = mock.Mock()
        self._get_chassis_physnets = mock.Mock()
        self._get_chassis_physnets.return_value = ['fake-physnet']
        self.get_chassis_and_physnets = mock.Mock()
        self.get_gateway_chassis_from_cms_options = mock.Mock()
        self.is_col_present = mock.Mock()
        self.is_col_present.return_value = False
        self.db_set = mock.Mock()
        self.lookup = mock.MagicMock()
        self.chassis_list = mock.MagicMock()
        self.is_table_present = mock.Mock()
        self.is_table_present.return_value = False
        self.get_chassis_by_card_serial_from_cms_options = mock.Mock()
        self.get_schema_version = mock.Mock(return_value='3.6.0')


class FakeOvsdbTransaction(object):
    def __init__(self, **kwargs):
        self.insert = mock.Mock()


class FakePlugin(object):

    def __init__(self, **kwargs):
        self.get_ports = mock.Mock()
        self._get_port_security_group_bindings = mock.Mock()


class FakeStandardAttribute(object):

    def __init__(self, _id=1, resource_type=mock.ANY, description=mock.ANY,
                 revision_number=1):
        self.id = _id
        self.resource_type = resource_type
        self.description = description
        self.revision_number = revision_number


class FakeQosNetworkPolicyBinding(object):

    def __init__(self, policy_id=mock.ANY, network_id=mock.ANY):
        self.policy_id = policy_id
        self.network_id = network_id


class FakeQosFIPPolicyBinding(object):

    def __init__(self, policy_id=mock.ANY, fip_id=mock.ANY):
        self.policy_id = policy_id
        self.fip_id = fip_id


class FakeResource(dict):

    def __init__(self, manager=None, info=None, loaded=False, methods=None):
        """Set attributes and methods for a resource.

        :param manager:
            The resource manager
        :param Dictionary info:
            A dictionary with all attributes
        :param bool loaded:
            True if the resource is loaded in memory
        :param Dictionary methods:
            A dictionary with all methods
        """
        info = info or {}
        super(FakeResource, self).__init__(info)
        methods = methods or {}

        self.__name__ = type(self).__name__
        self.manager = manager
        self._info = info
        self._add_details(info)
        self._add_methods(methods)
        self._loaded = loaded
        # Add a revision number by default
        setattr(self, 'revision_number', 1)

    @property
    def db_obj(self):
        return self

    def _add_details(self, info):
        for (k, v) in info.items():
            setattr(self, k, v)

    def _add_methods(self, methods):
        """Fake methods with MagicMock objects.

        For each <@key, @value> pairs in methods, add an callable MagicMock
        object named @key as an attribute, and set the mock's return_value to
        @value. When users access the attribute with (), @value will be
        returned, which looks like a function call.
        """
        for (name, ret) in methods.items():
            method = mock.MagicMock(return_value=ret)
            setattr(self, name, method)

    def __repr__(self):
        reprkeys = sorted(k for k in self.__dict__.keys() if k[0] != '_' and
                          k != 'manager')
        info = ", ".join("%s=%s" % (k, getattr(self, k)) for k in reprkeys)
        return "<%s %s>" % (self.__class__.__name__, info)

    def keys(self):
        return self._info.keys()

    def info(self):
        return self._info

    def update(self, info):
        super(FakeResource, self).update(info)
        self._add_details(info)


class FakeNetwork(object):
    """Fake one or more networks."""

    @staticmethod
    def create_one_network(attrs=None):
        """Create a fake network.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the network
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        network_attrs = {
            'id': 'network-id-' + fake_uuid,
            'name': 'network-name-' + fake_uuid,
            'status': 'ACTIVE',
            'tenant_id': 'project-id-' + fake_uuid,
            'admin_state_up': True,
            'shared': False,
            'subnets': [],
            'provider:network_type': 'geneve',
            'provider:physical_network': None,
            'provider:segmentation_id': 10,
            'router:external': False,
            'availability_zones': [],
            'availability_zone_hints': [],
            'is_default': False,
            'standard_attr_id': 1,
        }

        # Overwrite default attributes.
        network_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(network_attrs),
                            loaded=True)


class FakeNetworkContext(object):
    def __init__(self, network, segments):
        self.fake_network = network
        self.fake_segments = segments
        self._plugin_context = mock.MagicMock()

    @property
    def current(self):
        return self.fake_network

    @property
    def original(self):
        return None

    @property
    def network_segments(self):
        return self.fake_segments


class FakeSubnetContext(object):
    def __init__(self, subnet, original_subnet=None, network=None):
        self.fake_subnet = subnet
        self.fake_original_subnet = original_subnet
        self.fake_network = FakeNetworkContext(network, None)
        self._plugin_context = mock.MagicMock()

    @property
    def current(self):
        return self.fake_subnet

    @property
    def original(self):
        return self.fake_original_subnet

    @property
    def network(self):
        return self.fake_network


class FakeOvsdbRow(FakeResource):
    """Fake one or more OVSDB rows."""

    @staticmethod
    def create_one_ovsdb_row(attrs=None, methods=None):
        """Create a fake OVSDB row.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param Dictionary methods:
            A dictionary with all methods
        :return:
            A FakeResource object faking the OVSDB row
        """
        attrs = attrs or {}
        methods = methods or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        ovsdb_row_attrs = {
            'uuid': fake_uuid,
            'name': 'name-' + fake_uuid,
            'external_ids': {},
        }

        # Set default methods.
        ovsdb_row_methods = {
            'addvalue': None,
            'delete': None,
            'delvalue': None,
            'verify': None,
            'setkey': None,
        }

        # Overwrite default attributes and methods.
        ovsdb_row_attrs.update(attrs)
        ovsdb_row_methods.update(methods)

        result = FakeResource(info=copy.deepcopy(ovsdb_row_attrs),
                              loaded=True,
                              methods=copy.deepcopy(ovsdb_row_methods))
        result.setkey.side_effect = lambda col, k, v: (
                getattr(result, col).__setitem__(k, v))

        def fake_addvalue(col, val):
            try:
                getattr(result, col).append(val)
            except AttributeError:
                # Not all tests set up fake rows to have all used cols
                pass

        def fake_delvalue(col, val):
            try:
                getattr(result, col).remove(val)
            except (AttributeError, ValueError):
                # Some tests also fake adding values
                pass

        result.addvalue.side_effect = fake_addvalue
        result.delvalue.side_effect = fake_delvalue
        return result


class FakeOvsdbTable(FakeResource):
    """Fake one or more OVSDB tables."""

    @staticmethod
    def create_one_ovsdb_table(attrs=None, max_rows=sys.maxsize):
        """Create a fake OVSDB table.

        :param Dictionary attrs:
            A dictionary with all attributes
        :param Int max_rows:
            A num of max rows
        :return:
            A FakeResource object faking the OVSDB table
        """
        attrs = attrs or {}

        # Set default attributes.
        ovsdb_table_attrs = {
            'rows': collections.UserDict(),
            'columns': {},
            'indexes': [],
            'max_rows': max_rows,
        }

        # Overwrite default attributes.
        ovsdb_table_attrs.update(attrs)

        result = FakeResource(info=copy.deepcopy(ovsdb_table_attrs),
                              loaded=True)
        result.rows.indexes = {}
        return result


class FakePort(object):
    """Fake one or more ports."""

    @staticmethod
    def create_one_port(attrs=None):
        """Create a fake port.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the port
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        port_attrs = {
            'admin_state_up': True,
            'allowed_address_pairs': [{}],
            'binding:host_id': 'binding-host-id-' + fake_uuid,
            'binding:profile': {},
            'binding:vif_details': {},
            'binding:vif_type': 'ovs',
            'binding:vnic_type': 'normal',
            'device_id': 'device-id-' + fake_uuid,
            'device_owner': 'compute:nova',
            'dns_assignment': [{}],
            'dns_name': 'dns-name-' + fake_uuid,
            'extra_dhcp_opts': [{}],
            'fixed_ips': [{'subnet_id': 'subnet-id-' + fake_uuid,
                           'ip_address': '10.10.10.20'}],
            'id': 'port-id-' + fake_uuid,
            'mac_address': 'fa:16:3e:a9:4e:72',
            'name': 'port-name-' + fake_uuid,
            'network_id': 'network-id-' + fake_uuid,
            'port_security_enabled': True,
            'security_groups': [],
            'status': 'ACTIVE',
            'tenant_id': 'project-id-' + fake_uuid,
        }

        # Overwrite default attributes.
        port_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(port_attrs),
                            loaded=True)


class FakePortContext(object):
    def __init__(self, port, host, segments_to_bind):
        self.fake_port = port
        self.fake_host = host
        self.fake_segments_to_bind = segments_to_bind
        self.set_binding = mock.Mock()

    @property
    def current(self):
        return self.fake_port

    @property
    def host(self):
        return self.fake_host

    @property
    def segments_to_bind(self):
        return self.fake_segments_to_bind


class FakeSecurityGroup(object):
    """Fake one or more security groups."""

    @staticmethod
    def create_one_security_group(attrs=None):
        """Create a fake security group.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the security group
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        security_group_attrs = {
            'id': 'security-group-id-' + fake_uuid,
            'name': 'security-group-name-' + fake_uuid,
            'description': 'security-group-description-' + fake_uuid,
            'tenant_id': 'project-id-' + fake_uuid,
            'security_group_rules': [],
        }

        # Overwrite default attributes.
        security_group_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(security_group_attrs),
                            loaded=True)


class FakeSecurityGroupRule(object):
    """Fake one or more security group rules."""

    @staticmethod
    def create_one_security_group_rule(attrs=None):
        """Create a fake security group rule.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the security group rule
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        security_group_rule_attrs = {
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'id': 'security-group-rule-id-' + fake_uuid,
            'port_range_max': 22,
            'port_range_min': 22,
            'protocol': 'tcp',
            'remote_group_id': None,
            'remote_ip_prefix': '0.0.0.0/0',
            'normalized_cidr': '0.0.0.0/0',
            'security_group_id': 'security-group-id-' + fake_uuid,
            'tenant_id': 'project-id-' + fake_uuid,
        }

        # Overwrite default attributes.
        security_group_rule_attrs.update(attrs)

        if ('remote_ip_prefix' in attrs and 'normalized_cidr' not in attrs):
            if attrs['remote_ip_prefix'] is None:
                security_group_rule_attrs['normalized_cidr'] = None
            else:
                security_group_rule_attrs['normalized_cidr'] = (
                        net.AuthenticIPNetwork(attrs['remote_ip_prefix']))

        return FakeResource(info=copy.deepcopy(security_group_rule_attrs),
                            loaded=True)


class FakeSegment(object):
    """Fake one or more segments."""

    @staticmethod
    def create_one_segment(attrs=None):
        """Create a fake segment.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the segment
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        segment_attrs = {
            'id': 'segment-id-' + fake_uuid,
            'network_type': 'geneve',
            'physical_network': None,
            'segmentation_id': 10,
        }

        # Overwrite default attributes.
        segment_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(segment_attrs),
                            loaded=True)


class FakeSubnet(object):
    """Fake one or more subnets."""

    @staticmethod
    def create_one_subnet(attrs=None):
        """Create a fake subnet.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the subnet
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        subnet_attrs = {
            'id': 'subnet-id-' + fake_uuid,
            'name': 'subnet-name-' + fake_uuid,
            'network_id': 'network-id-' + fake_uuid,
            'cidr': '10.10.10.0/24',
            'tenant_id': 'project-id-' + fake_uuid,
            'enable_dhcp': True,
            'dns_nameservers': [],
            'allocation_pools': [],
            'host_routes': [],
            'ip_version': 4,
            'gateway_ip': '10.10.10.1',
            'ipv6_address_mode': 'None',
            'ipv6_ra_mode': 'None',
            'subnetpool_id': None,
        }

        # Overwrite default attributes.
        subnet_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(subnet_attrs),
                            loaded=True)


class FakeFloatingIp(object):
    """Fake one or more floating ips."""

    @staticmethod
    def create_one_fip(attrs=None):
        """Create a fake floating ip.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the floating ip
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        fip_attrs = {
            'id': 'fip-id-' + fake_uuid,
            'tenant_id': '',
            'fixed_ip_address': '10.0.0.10',
            'fixed_port': FakePort.create_one_port(),
            'floating_ip_address': '172.21.0.100',
            'router_id': 'router-id',
            'port_id': 'port_id',
            'fixed_port_id': 'port_id',
            'floating_port_id': 'fip-port-id',
            'status': 'Active',
            'floating_network_id': 'fip-net-id',
            'dns': '',
            'dns_domain': '',
            'dns_name': '',
            'project_id': '',
            'standard_attr': FakeStandardAttribute(),
            'qos_policy_binding': FakeQosFIPPolicyBinding(),
            'qos_network_policy_binding': FakeQosNetworkPolicyBinding(),
        }

        # Overwrite default attributes.
        fip_attrs.update(attrs)

        return FakeResource(info=copy.deepcopy(fip_attrs),
                            loaded=True)


class FakeOVNPort(object):
    """Fake one or more ports."""

    @staticmethod
    def create_one_port(attrs=None):
        """Create a fake ovn port.

        :param Dictionary attrs:
            A dictionary with all attributes
        :return:
            A FakeResource object faking the port
        """
        attrs = attrs or {}

        # Set default attributes.
        fake_uuid = uuidutils.generate_uuid()
        port_attrs = {
            'addresses': [],
            'dhcpv4_options': '',
            'dhcpv6_options': [],
            'enabled': True,
            'external_ids': {},
            'name': fake_uuid,
            'options': {},
            'parent_name': [],
            'port_security': [],
            'tag': [],
            'tag_request': [],
            'type': '',
            'up': False,
        }

        # Overwrite default attributes.
        port_attrs.update(attrs)
        return type('Logical_Switch_Port', (object, ), port_attrs)

    @staticmethod
    def from_neutron_port(port):
        """Create a fake ovn port based on a neutron port."""
        external_ids = {
            ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY:
                ovn_utils.ovn_name(port['network_id']),
            ovn_const.OVN_SG_IDS_EXT_ID_KEY:
                ' '.join(port['security_groups']),
            ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                port.get('device_owner', '')}
        addresses = [port['mac_address'], ]
        addresses += [x['ip_address'] for x in port.get('fixed_ips', [])]
        port_security = (
            addresses + [x['ip_address'] for x in
                         port.get('allowed_address_pairs', [])])
        return FakeOVNPort.create_one_port(
            {'external_ids': external_ids, 'addresses': addresses,
             'port_security': port_security})


FakeStaticRoute = collections.namedtuple(
    'Static_Routes', ['ip_prefix', 'nexthop', 'external_ids'])


class FakeOVNRouter(object):

    @staticmethod
    def create_one_router(attrs=None):
        router_attrs = {
            'enabled': False,
            'external_ids': {},
            'load_balancer': [],
            'name': '',
            'nat': [],
            'options': {},
            'ports': [],
            'static_routes': [],
        }

        # Overwrite default attributes.
        router_attrs.update(attrs)
        return type('Logical_Router', (object, ), router_attrs)

    @staticmethod
    def from_neutron_router(router):

        def _get_subnet_id(gw_info):
            subnet_id = ''
            ext_ips = gw_info.get('external_fixed_ips', [])
            if ext_ips:
                subnet_id = ext_ips[0]['subnet_id']
            return subnet_id

        external_ids = {
            ovn_const.OVN_GW_PORT_EXT_ID_KEY: router.get('gw_port_id') or '',
            ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY:
                router.get('name', 'no_router_name')}

        # Get the routes
        routes = []
        for r in router.get('routes', []):
            routes.append(FakeStaticRoute(ip_prefix=r['destination'],
                                          nexthop=r['nexthop'],
                                          external_ids={}))

        gw_info = router.get(l3.EXTERNAL_GW_INFO)
        if gw_info:
            external_ids = {
                ovn_const.OVN_ROUTER_IS_EXT_GW: 'true',
                ovn_const.OVN_SUBNET_EXT_ID_KEY: _get_subnet_id(gw_info)}
            routes.append(FakeStaticRoute(
                ip_prefix='0.0.0.0/0', nexthop='',
                external_ids=external_ids))

        return FakeOVNRouter.create_one_router(
            {'external_ids': external_ids,
             'enabled': router.get('admin_state_up') or False,
             'name': ovn_utils.ovn_name(router['id']),
             'static_routes': routes})


class FakeChassis(object):

    @staticmethod
    def create(attrs=None, az_list=None, chassis_as_gw=False,
               bridge_mappings=None, rp_bandwidths=None,
               rp_inventory_defaults=None, rp_hypervisors=None,
               card_serial_number=None):
        cms_opts = []
        if az_list:
            cms_opts.append("%s=%s" % (ovn_const.CMS_OPT_AVAILABILITY_ZONES,
                                       ':'.join(az_list)))
        if chassis_as_gw:
            cms_opts.append(ovn_const.CMS_OPT_CHASSIS_AS_GW)

        if rp_bandwidths:
            cms_opts.append('%s=%s' % (n_const.RP_BANDWIDTHS,
                                       ';'.join(rp_bandwidths)))
        elif rp_bandwidths == '':  # Test wrongly defined parameter
            cms_opts.append('%s=' % n_const.RP_BANDWIDTHS)

        if rp_inventory_defaults:
            inv_defaults = ';'.join('%s:%s' % (key, value) for key, value in
                                    rp_inventory_defaults.items())
            cms_opts.append('%s=%s' % (n_const.RP_INVENTORY_DEFAULTS,
                                       inv_defaults))
        elif rp_inventory_defaults == '':  # Test wrongly defined parameter
            cms_opts.append('%s=' % n_const.RP_INVENTORY_DEFAULTS)

        if rp_hypervisors:
            cms_opts.append('%s=%s' % (ovn_const.RP_HYPERVISORS,
                                       ';'.join(rp_hypervisors)))
        elif rp_hypervisors == '':  # Test wrongly defined parameter
            cms_opts.append('%s=' % ovn_const.RP_HYPERVISORS)

        if card_serial_number:
            cms_opts.append('%s=%s' % (ovn_const.CMS_OPT_CARD_SERIAL_NUMBER,
                                       card_serial_number))

        # NOTE(ralonsoh): LP#1990229, once min OVN version >= 20.06, the CMS
        # options and the bridge mappings should be stored only in
        # "other_config".
        other_config = {}
        if cms_opts:
            other_config[ovn_const.OVN_CMS_OPTIONS] = ','.join(cms_opts)

        if bridge_mappings:
            other_config['ovn-bridge-mappings'] = ','.join(bridge_mappings)

        chassis_attrs = {
            'encaps': [],
            'external_ids': '',
            'hostname': '',
            'name': uuidutils.generate_uuid(),
            'nb_cfg': 0,
            'other_config': other_config,
            'transport_zones': [],
            'vtep_logical_switches': []}

        # Overwrite default attributes.
        chassis_attrs.update(attrs or {})
        return type('Chassis', (object, ), chassis_attrs)
