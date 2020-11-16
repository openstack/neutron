# Copyright 2020 Red Hat, Inc.
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

import mock
from oslo_config import cfg

from futurist import periodics
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib import constants as n_const
from neutron_lib import context as n_context

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as ovn_config
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import maintenance
from neutron.tests.functional import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_extraroute


class _TestMaintenanceHelper(base.TestOVNFunctionalBase):
    """A helper class to keep the code more organized."""

    def setUp(self):
        super(_TestMaintenanceHelper, self).setUp()
        self._ovn_client = self.mech_driver._ovn_client
        self._l3_ovn_client = self.l3_plugin._ovn_client
        ext_mgr = test_extraroute.ExtraRouteTestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.maint = maintenance.DBInconsistenciesPeriodics(self._ovn_client)
        self.context = n_context.get_admin_context()
        # Always verify inconsistencies for all objects.
        db_rev.INCONSISTENCIES_OLDER_THAN = -1

    def _find_network_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Switch'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY) == name):
                return row

    def _create_network(self, name, external=False):
        data = {'network': {'name': name, 'tenant_id': self._tenant_id,
                            extnet_apidef.EXTERNAL: external}}
        req = self.new_create_request('networks', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['network']

    def _update_network_name(self, net_id, new_name):
        data = {'network': {'name': new_name}}
        req = self.new_update_request('networks', data, net_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['network']

    def _create_port(self, name, net_id, security_groups=None,
                     device_owner=None):
        data = {'port': {'name': name,
                         'tenant_id': self._tenant_id,
                         'network_id': net_id}}

        if security_groups is not None:
            data['port']['security_groups'] = security_groups

        if device_owner is not None:
            data['port']['device_owner'] = device_owner

        req = self.new_create_request('ports', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']

    def _update_port_name(self, port_id, new_name):
        data = {'port': {'name': new_name}}
        req = self.new_update_request('ports', data, port_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']

    def _find_port_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Switch_Port'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_PORT_NAME_EXT_ID_KEY) == name):
                return row

    def _set_global_dhcp_opts(self, ip_version, opts):
        opt_string = ','.join(['{0}:{1}'.format(key, value)
                               for key, value
                               in opts.items()])
        if ip_version == 6:
            ovn_config.cfg.CONF.set_override('ovn_dhcp6_global_options',
                                             opt_string,
                                             group='ovn')
        if ip_version == 4:
            ovn_config.cfg.CONF.set_override('ovn_dhcp4_global_options',
                                             opt_string,
                                             group='ovn')

    def _unset_global_dhcp_opts(self, ip_version):
        if ip_version == 6:
            ovn_config.cfg.CONF.clear_override('ovn_dhcp6_global_options',
                                               group='ovn')
        if ip_version == 4:
            ovn_config.cfg.CONF.clear_override('ovn_dhcp4_global_options',
                                               group='ovn')

    def _create_subnet(self, name, net_id, ip_version=4):
        data = {'subnet': {'name': name,
                           'tenant_id': self._tenant_id,
                           'network_id': net_id,
                           'ip_version': ip_version,
                           'enable_dhcp': True}}
        if ip_version == 4:
            data['subnet']['cidr'] = '10.0.0.0/24'
        else:
            data['subnet']['cidr'] = 'eef0::/64'

        req = self.new_create_request('subnets', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['subnet']

    def _update_subnet_enable_dhcp(self, subnet_id, value):
        data = {'subnet': {'enable_dhcp': value}}
        req = self.new_update_request('subnets', data, subnet_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['subnet']

    def _find_subnet_row_by_id(self, subnet_id):
        for row in self.nb_api._tables['DHCP_Options'].rows.values():
            if (row.external_ids.get('subnet_id') == subnet_id and
               not row.external_ids.get('port_id')):
                return row

    def _create_router(self, name, external_gateway_info=None):
        data = {'router': {'name': name, 'tenant_id': self._tenant_id}}
        if external_gateway_info is not None:
            data['router']['external_gateway_info'] = external_gateway_info
        req = self.new_create_request('routers', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['router']

    def _update_router_name(self, net_id, new_name):
        data = {'router': {'name': new_name}}
        req = self.new_update_request('routers', data, net_id, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['router']

    def _find_router_row_by_name(self, name):
        for row in self.nb_api._tables['Logical_Router'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY) == name):
                return row

    def _create_security_group(self):
        data = {'security_group': {'name': 'sgtest',
                                   'tenant_id': self._tenant_id,
                                   'description': 'SpongeBob Rocks!'}}
        req = self.new_create_request('security-groups', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['security_group']

    def _find_security_group_row_by_id(self, sg_id):
        for row in self.nb_api._tables['Port_Group'].rows.values():
            if row.name == utils.ovn_port_group_name(sg_id):
                return row

    def _create_security_group_rule(self, sg_id):
        data = {'security_group_rule': {'security_group_id': sg_id,
                                        'direction': 'ingress',
                                        'protocol': n_const.PROTO_NAME_TCP,
                                        'ethertype': n_const.IPv4,
                                        'port_range_min': 22,
                                        'port_range_max': 22,
                                        'tenant_id': self._tenant_id}}
        req = self.new_create_request('security-group-rules', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['security_group_rule']

    def _find_security_group_rule_row_by_id(self, sgr_id):
        for row in self.nb_api._tables['ACL'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_SG_RULE_EXT_ID_KEY) == sgr_id):
                return row

    def _process_router_interface(self, action, router_id, subnet_id):
        req = self.new_action_request(
            'routers', {'subnet_id': subnet_id}, router_id,
            '%s_router_interface' % action)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)

    def _add_router_interface(self, router_id, subnet_id):
        return self._process_router_interface('add', router_id, subnet_id)

    def _remove_router_interface(self, router_id, subnet_id):
        return self._process_router_interface('remove', router_id, subnet_id)

    def _find_router_port_row_by_port_id(self, port_id):
        for row in self.nb_api._tables['Logical_Router_Port'].rows.values():
            if row.name == utils.ovn_lrouter_port_name(port_id):
                return row


class TestMaintenance(_TestMaintenanceHelper):

    def test_network(self):
        net_name = 'networktest'
        with mock.patch.object(self._ovn_client, 'create_network'):
            neutron_obj = self._create_network(net_name)

        # Assert the network doesn't exist in OVN
        self.assertIsNone(self._find_network_row_by_name(net_name))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the network was now created
        ovn_obj = self._find_network_row_by_name(net_name)
        self.assertIsNotNone(ovn_obj)
        self.assertEqual(
            neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Update

        new_obj_name = 'networktest_updated'
        with mock.patch.object(self._ovn_client, 'update_network'):
            new_neutron_obj = self._update_network_name(neutron_obj['id'],
                                                        new_obj_name)

        # Assert the revision numbers are out-of-sync
        ovn_obj = self._find_network_row_by_name(net_name)
        self.assertNotEqual(
            new_neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the old name doesn't exist anymore in the OVNDB
        self.assertIsNone(self._find_network_row_by_name(net_name))

        # Assert the network is now in sync
        ovn_obj = self._find_network_row_by_name(new_obj_name)
        self.assertEqual(
            new_neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Delete

        with mock.patch.object(self._ovn_client, 'delete_network'):
            self._delete('networks', new_neutron_obj['id'])

        # Assert the network still exists in OVNDB
        self.assertIsNotNone(self._find_network_row_by_name(new_obj_name))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the network is now deleted from OVNDB
        self.assertIsNone(self._find_network_row_by_name(new_obj_name))

        # Assert the revision number no longer exists
        self.assertIsNone(db_rev.get_revision_row(
            self.context,
            new_neutron_obj['id']))

    def test_port(self):
        obj_name = 'porttest'
        neutron_net = self._create_network('network1')

        with mock.patch.object(self._ovn_client, 'create_port'):
            neutron_obj = self._create_port(obj_name, neutron_net['id'])

        # Assert the port doesn't exist in OVN
        self.assertIsNone(self._find_port_row_by_name(obj_name))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the port was now created
        ovn_obj = self._find_port_row_by_name(obj_name)
        self.assertIsNotNone(ovn_obj)
        self.assertEqual(
            neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Update

        new_obj_name = 'porttest_updated'
        with mock.patch.object(self._ovn_client, 'update_port'):
            new_neutron_obj = self._update_port_name(neutron_obj['id'],
                                                     new_obj_name)

        # Assert the revision numbers are out-of-sync
        ovn_obj = self._find_port_row_by_name(obj_name)
        self.assertNotEqual(
            new_neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the old name doesn't exist anymore in the OVNDB
        self.assertIsNone(self._find_port_row_by_name(obj_name))

        # Assert the port is now in sync. Note that for ports we are
        # fetching it again from the Neutron database prior to comparison
        # because of the monitor code that can update the ports again upon
        # changes to it.
        ovn_obj = self._find_port_row_by_name(new_obj_name)
        new_neutron_obj = self._ovn_client._plugin.get_port(
            self.context, neutron_obj['id'])
        self.assertEqual(
            new_neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Delete

        with mock.patch.object(self._ovn_client, 'delete_port'):
            self._delete('ports', new_neutron_obj['id'])

        # Assert the port still exists in OVNDB
        self.assertIsNotNone(self._find_port_row_by_name(new_obj_name))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the port is now deleted from OVNDB
        self.assertIsNone(self._find_port_row_by_name(new_obj_name))

        # Assert the revision number no longer exists
        self.assertIsNone(db_rev.get_revision_row(
            self.context,
            neutron_obj['id']))

    def test_subnet_global_dhcp4_opts(self):
        obj_name = 'globaltestsubnet'
        options = {'ntp_server': '1.2.3.4'}
        neutron_net = self._create_network('network1')

        # Create a subnet without global options
        neutron_sub = self._create_subnet(obj_name, neutron_net['id'])

        # Assert that the option is not set
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertIsNone(ovn_obj.options.get('ntp_server', None))

        # Set some global DHCP Options
        self._set_global_dhcp_opts(ip_version=4, opts=options)

        # Run the maintenance task to add the new options
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_global_dhcp_opts)

        # Assert that the option was added
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertEqual(
            ovn_obj.options.get('ntp_server', None),
            '1.2.3.4')

        # Change the global option
        new_options = {'ntp_server': '4.3.2.1'}
        self._set_global_dhcp_opts(ip_version=4, opts=new_options)

        # Run the maintenance task to update the options
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_global_dhcp_opts)

        # Assert that the option was changed
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertEqual(
            ovn_obj.options.get('ntp_server', None),
            '4.3.2.1')

        # Change the global option to null
        new_options = {'ntp_server': ''}
        self._set_global_dhcp_opts(ip_version=4, opts=new_options)

        # Run the maintenance task to update the options
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_global_dhcp_opts)

        # Assert that the option was removed
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertIsNone(ovn_obj.options.get('ntp_server', None))

    def test_subnet_global_dhcp6_opts(self):
        obj_name = 'globaltestsubnet'
        options = {'ntp_server': '1.2.3.4'}
        neutron_net = self._create_network('network1')

        # Create a subnet without global options
        neutron_sub = self._create_subnet(obj_name, neutron_net['id'], 6)

        # Assert that the option is not set
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertIsNone(ovn_obj.options.get('ntp_server', None))

        # Set some global DHCP Options
        self._set_global_dhcp_opts(ip_version=6, opts=options)

        # Run the maintenance task to add the new options
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_global_dhcp_opts)

        # Assert that the option was added
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertEqual(
            ovn_obj.options.get('ntp_server', None),
            '1.2.3.4')

        # Change the global option
        new_options = {'ntp_server': '4.3.2.1'}
        self._set_global_dhcp_opts(ip_version=6, opts=new_options)

        # Run the maintenance task to update the options
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_global_dhcp_opts)

        # Assert that the option was changed
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertEqual(
            ovn_obj.options.get('ntp_server', None),
            '4.3.2.1')

        # Change the global option to null
        new_options = {'ntp_server': ''}
        self._set_global_dhcp_opts(ip_version=6, opts=new_options)

        # Run the maintenance task to update the options
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_global_dhcp_opts)

        # Assert that the option was removed
        ovn_obj = self._find_subnet_row_by_id(neutron_sub['id'])
        self.assertIsNone(ovn_obj.options.get('ntp_server', None))

    def test_subnet(self):
        obj_name = 'subnettest'
        neutron_net = self._create_network('network1')

        with mock.patch.object(self._ovn_client, 'create_subnet'):
            neutron_obj = self._create_subnet(obj_name, neutron_net['id'])

        # Assert the subnet doesn't exist in OVN
        self.assertIsNone(self._find_subnet_row_by_id(neutron_obj['id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the subnet was now created
        ovn_obj = self._find_subnet_row_by_id(neutron_obj['id'])
        self.assertIsNotNone(ovn_obj)
        self.assertEqual(
            neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Update

        with mock.patch.object(self._ovn_client, 'update_subnet'):
            neutron_obj = self._update_subnet_enable_dhcp(
                neutron_obj['id'], False)

        # Assert the revision numbers are out-of-sync
        ovn_obj = self._find_subnet_row_by_id(neutron_obj['id'])
        self.assertNotEqual(
            neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the old name doesn't exist anymore in the OVNDB. When
        # the subnet's enable_dhcp's is set to False, OVN will remove the
        # DHCP_Options entry related to that subnet.
        self.assertIsNone(self._find_subnet_row_by_id(neutron_obj['id']))

        # Re-enable the DHCP for the subnet and check if the maintenance
        # thread will re-create it in OVN
        with mock.patch.object(self._ovn_client, 'update_subnet'):
            neutron_obj = self._update_subnet_enable_dhcp(
                neutron_obj['id'], True)

        # Assert the DHCP_Options still doesn't exist in OVNDB
        self.assertIsNone(self._find_subnet_row_by_id(neutron_obj['id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the subnet is now in sync
        ovn_obj = self._find_subnet_row_by_id(neutron_obj['id'])
        self.assertEqual(
            neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Delete

        with mock.patch.object(self._ovn_client, 'delete_subnet'):
            self._delete('subnets', neutron_obj['id'])

        # Assert the subnet still exists in OVNDB
        self.assertIsNotNone(self._find_subnet_row_by_id(neutron_obj['id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the subnet is now deleted from OVNDB
        self.assertIsNone(self._find_subnet_row_by_id(neutron_obj['id']))

        # Assert the revision number no longer exists
        self.assertIsNone(db_rev.get_revision_row(
            self.context,
            neutron_obj['id']))

    def test_router(self):
        obj_name = 'routertest'

        with mock.patch.object(self._l3_ovn_client, 'create_router'):
            neutron_obj = self._create_router(obj_name)

        # Assert the router doesn't exist in OVN
        self.assertIsNone(self._find_router_row_by_name(obj_name))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the router was now created
        ovn_obj = self._find_router_row_by_name(obj_name)
        self.assertIsNotNone(ovn_obj)
        self.assertEqual(
            neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Update

        new_obj_name = 'routertest_updated'
        with mock.patch.object(self._l3_ovn_client, 'update_router'):
            new_neutron_obj = self._update_router_name(neutron_obj['id'],
                                                       new_obj_name)

        # Assert the revision numbers are out-of-sync
        ovn_obj = self._find_router_row_by_name(obj_name)
        self.assertNotEqual(
            new_neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the old name doesn't exist anymore in the OVNDB
        self.assertIsNone(self._find_router_row_by_name(obj_name))

        # Assert the router is now in sync
        ovn_obj = self._find_router_row_by_name(new_obj_name)
        self.assertEqual(
            new_neutron_obj['revision_number'],
            int(ovn_obj.external_ids[ovn_const.OVN_REV_NUM_EXT_ID_KEY]))

        # > Delete

        with mock.patch.object(self._l3_ovn_client, 'delete_router'):
            self._delete('routers', new_neutron_obj['id'])

        # Assert the router still exists in OVNDB
        self.assertIsNotNone(self._find_router_row_by_name(new_obj_name))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the router is now deleted from OVNDB
        self.assertIsNone(self._find_router_row_by_name(new_obj_name))

        # Assert the revision number no longer exists
        self.assertIsNone(db_rev.get_revision_row(
            self.context,
            new_neutron_obj['id']))

    def test_security_group(self):
        with mock.patch.object(self._ovn_client, 'create_security_group'):
            neutron_obj = self._create_security_group()

        # Assert the sg doesn't exist in OVN
        self.assertIsNone(
            self._find_security_group_row_by_id(neutron_obj['id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the sg was now created. We don't save the revision number
        # in the Security Group because OVN doesn't support updating it,
        # all we care about is whether it exists or not.
        self.assertIsNotNone(
            self._find_security_group_row_by_id(neutron_obj['id']))

        # > Delete

        with mock.patch.object(self._ovn_client, 'delete_security_group'):
            self._delete('security-groups', neutron_obj['id'])

        # Assert the sg still exists in OVNDB
        self.assertIsNotNone(
            self._find_security_group_row_by_id(neutron_obj['id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the sg is now deleted from OVNDB
        self.assertIsNone(
            self._find_security_group_row_by_id(neutron_obj['id']))

        # Assert the revision number no longer exists
        self.assertIsNone(db_rev.get_revision_row(
            self.context,
            neutron_obj['id']))

    def test_security_group_rule(self):
        neutron_sg = self._create_security_group()
        neutron_net = self._create_network('network1')
        self._create_port('portsgtest', neutron_net['id'],
                          security_groups=[neutron_sg['id']])

        with mock.patch.object(self._ovn_client, 'create_security_group_rule'):
            neutron_obj = self._create_security_group_rule(neutron_sg['id'])

        # Assert the sg rule doesn't exist in OVN
        self.assertIsNone(
            self._find_security_group_rule_row_by_id(neutron_obj['id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the sg rule was now created. We don't save the revision number
        # in the Security Group because OVN doesn't support updating it,
        # all we care about is whether it exists or not.
        self.assertIsNotNone(
            self._find_security_group_rule_row_by_id(neutron_obj['id']))

        # > Delete

        # FIXME(lucasagomes): Maintenance thread fixing deleted
        # security group rules is currently broken due to:
        # https://bugs.launchpad.net/networking-ovn/+bug/1756123

    def test_router_port(self):
        neutron_net = self._create_network('networktest', external=True)
        neutron_subnet = self._create_subnet('subnettest', neutron_net['id'])
        neutron_router = self._create_router('routertest')

        with mock.patch.object(self._l3_ovn_client, 'create_router_port'):
            with mock.patch('neutron.db.ovn_revision_numbers_db.'
                            'bump_revision'):
                neutron_obj = self._add_router_interface(neutron_router['id'],
                                                         neutron_subnet['id'])

        # Assert the router port doesn't exist in OVN
        self.assertIsNone(
            self._find_router_port_row_by_port_id(neutron_obj['port_id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the router port was now created
        self.assertIsNotNone(
            self._find_router_port_row_by_port_id(neutron_obj['port_id']))

        # > Delete

        with mock.patch.object(self._l3_ovn_client, 'delete_router_port'):
            self._remove_router_interface(neutron_router['id'],
                                          neutron_subnet['id'])

        # Assert the router port still exists in OVNDB
        self.assertIsNotNone(
            self._find_router_port_row_by_port_id(neutron_obj['port_id']))

        # Call the maintenance thread to fix the problem
        self.maint.check_for_inconsistencies()

        # Assert the router port is now deleted from OVNDB
        self.assertIsNone(
            self._find_router_port_row_by_port_id(neutron_obj['port_id']))

        # Assert the revision number no longer exists
        self.assertIsNone(db_rev.get_revision_row(
            self.context,
            neutron_obj['port_id']))

    def test_check_metadata_ports(self):
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled', True,
                                         group='ovn')
        neutron_net = self._create_network('network1')
        metadata_port = self._ovn_client._find_metadata_port(
            self.context, neutron_net['id'])

        # Assert the metadata port exists
        self.assertIsNotNone(metadata_port)

        # Delete the metadata port
        self._delete('ports', metadata_port['id'])

        metadata_port = self._ovn_client._find_metadata_port(
            self.context, neutron_net['id'])

        # Assert the metadata port is gone
        self.assertIsNone(metadata_port)

        # Call the maintenance thread to fix the problem, it will raise
        # NeverAgain so that the job only runs once at startup
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_metadata_ports)

        metadata_port = self._ovn_client._find_metadata_port(
            self.context, neutron_net['id'])

        # Assert the metadata port was re-created
        self.assertIsNotNone(metadata_port)

    def test_check_metadata_ports_not_enabled(self):
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled', False,
                                         group='ovn')
        with mock.patch.object(self._ovn_client,
                               'create_metadata_port') as mock_create_port:
            self.assertRaises(periodics.NeverAgain,
                              self.maint.check_metadata_ports)
            # Assert create_metadata_port() wasn't called since metadata
            # is not enabled
            self.assertFalse(mock_create_port.called)

    def test_check_for_port_security_unknown_address(self):
        neutron_net = self._create_network('network1')
        neutron_port = self._create_port('port1', neutron_net['id'])

        # Let's force disabling port security for the LSP
        self.nb_api.lsp_set_port_security(neutron_port['id'], []).execute(
            check_error=True)

        ovn_port = self.nb_api.db_find(
            'Logical_Switch_Port', ('name', '=', neutron_port['id'])).execute(
            check_error=True)[0]

        # Assert that port security is now disabled but the 'unknown'
        # is not set in the addresses column
        self.assertFalse(ovn_port['port_security'])
        self.assertNotIn('unknown', ovn_port['addresses'])

        # Call the maintenance task to fix the problem. Note that
        # NeverAgain is raised so it only runs once at start up
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_for_port_security_unknown_address)

        ovn_port = self.nb_api.db_find(
            'Logical_Switch_Port', ('name', '=', neutron_port['id'])).execute(
            check_error=True)[0]

        # Assert that 'unknown' was set in the addresses column for
        # the port
        self.assertFalse(ovn_port['port_security'])
        self.assertIn('unknown', ovn_port['addresses'])

        # Now the other way around, let's set port_security in the OVN
        # table while the 'unknown' address is set in the addresses column
        self.nb_api.lsp_set_port_security(
            neutron_port['id'], ovn_port['addresses']).execute(
            check_error=True)

        ovn_port = self.nb_api.db_find(
            'Logical_Switch_Port', ('name', '=', neutron_port['id'])).execute(
            check_error=True)[0]

        self.assertTrue(ovn_port['port_security'])
        self.assertIn('unknown', ovn_port['addresses'])

        # Call the maintenance task to fix the problem. Note that
        # NeverAgain is raised so it only runs once at start up
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_for_port_security_unknown_address)

        ovn_port = self.nb_api.db_find(
            'Logical_Switch_Port', ('name', '=', neutron_port['id'])).execute(
            check_error=True)[0]

        # Assert that 'unknown' was removed from the addresses column
        # for the port
        self.assertTrue(ovn_port['port_security'])
        self.assertNotIn('unknown', ovn_port['addresses'])

    def test_check_for_igmp_snooping_enabled(self):
        cfg.CONF.set_override('igmp_snooping_enable', False, group='OVS')
        net = self._create_network('net')
        ls = self.nb_api.db_find('Logical_Switch',
            ('name', '=', utils.ovn_name(net['id']))).execute(
            check_error=True)[0]

        self.assertEqual('false', ls['other_config'][ovn_const.MCAST_SNOOP])
        self.assertEqual(
            'false', ls['other_config'][ovn_const.MCAST_FLOOD_UNREGISTERED])

        # Change the value of the configuration
        cfg.CONF.set_override('igmp_snooping_enable', True, group='OVS')

        # Call the maintenance task and check that the value has been
        # updated in the Logical Switch
        self.assertRaises(periodics.NeverAgain,
                          self.maint.check_for_igmp_snoop_support)

        ls = self.nb_api.db_find('Logical_Switch',
            ('name', '=', utils.ovn_name(net['id']))).execute(
            check_error=True)[0]

        self.assertEqual('true', ls['other_config'][ovn_const.MCAST_SNOOP])
        self.assertEqual(
            'false', ls['other_config'][ovn_const.MCAST_FLOOD_UNREGISTERED])
