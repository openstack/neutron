# Copyright 2014 Citrix Systems
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

import contextlib

import mock

from neutron.common import exceptions
from neutron import context
from neutron.db.loadbalancer import loadbalancer_db
from neutron import manager
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers.netscaler import ncc_client
from neutron.services.loadbalancer.drivers.netscaler import netscaler_driver
from neutron.tests.unit.db.loadbalancer import test_db_loadbalancer


LBAAS_DRIVER_CLASS = ('neutron.services.loadbalancer.drivers'
                      '.netscaler.netscaler_driver'
                      '.NetScalerPluginDriver')

NCC_CLIENT_CLASS = ('neutron.services.loadbalancer.drivers'
                    '.netscaler.ncc_client'
                    '.NSClient')

LBAAS_PROVIDER_NAME = 'netscaler'
LBAAS_PROVIDER = ('LOADBALANCER:%s:%s:default' %
                  (LBAAS_PROVIDER_NAME, LBAAS_DRIVER_CLASS))

#Test data
TESTVIP_ID = '52ab5d71-6bb2-457f-8414-22a4ba55efec'
TESTPOOL_ID = 'da477c13-24cd-4c9f-8c19-757a61ef3b9d'
TESTMEMBER_ID = '84dea8bc-3416-4fb0-83f9-2ca6e7173bee'
TESTMONITOR_ID = '9b9245a2-0413-4f15-87ef-9a41ef66048c'

TESTVIP_PORT_ID = '327d9662-ade9-4c74-aaf6-c76f145c1180'
TESTPOOL_PORT_ID = '132c1dbb-d3d8-45aa-96e3-71f2ea51651e'
TESTPOOL_SNATIP_ADDRESS = '10.0.0.50'
TESTPOOL_SNAT_PORT = {
    'id': TESTPOOL_PORT_ID,
    'fixed_ips': [{'ip_address': TESTPOOL_SNATIP_ADDRESS}]
}
TESTVIP_IP = '10.0.1.100'
TESTMEMBER_IP = '10.0.0.5'


class TestLoadBalancerPluginBase(test_db_loadbalancer
                                 .LoadBalancerPluginDbTestCase):

    def setUp(self):
        super(TestLoadBalancerPluginBase, self).setUp(
            lbaas_provider=LBAAS_PROVIDER)
        loaded_plugins = manager.NeutronManager().get_service_plugins()
        self.plugin_instance = loaded_plugins[constants.LOADBALANCER]


class TestNetScalerPluginDriver(TestLoadBalancerPluginBase):

    """Unit tests for the NetScaler LBaaS driver module."""

    def setUp(self):
        mock.patch.object(netscaler_driver, 'LOG').start()

        # mock the NSClient class (REST client)
        client_mock_cls = mock.patch(NCC_CLIENT_CLASS).start()

        #mock the REST methods of the NSClient class
        self.client_mock_instance = client_mock_cls.return_value
        self.create_resource_mock = self.client_mock_instance.create_resource
        self.create_resource_mock.side_effect = mock_create_resource_func
        self.update_resource_mock = self.client_mock_instance.update_resource
        self.update_resource_mock.side_effect = mock_update_resource_func
        self.retrieve_resource_mock = (self.client_mock_instance
                                           .retrieve_resource)
        self.retrieve_resource_mock.side_effect = mock_retrieve_resource_func
        self.remove_resource_mock = self.client_mock_instance.remove_resource
        self.remove_resource_mock.side_effect = mock_remove_resource_func
        super(TestNetScalerPluginDriver, self).setUp()
        self.plugin_instance.drivers[LBAAS_PROVIDER_NAME] = (
            netscaler_driver.NetScalerPluginDriver(self.plugin_instance))
        self.driver = self.plugin_instance.drivers[LBAAS_PROVIDER_NAME]
        self.context = context.get_admin_context()

    def test_create_vip(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                testvip = self._build_testvip_contents(subnet['subnet'],
                                                       pool['pool'])
                expectedvip = self._build_expectedvip_contents(
                    testvip,
                    subnet['subnet'])
                # mock the LBaaS plugin update_status().
                self._mock_update_status()
                # reset the create_resource() mock
                self.create_resource_mock.reset_mock()
                # execute the method under test
                self.driver.create_vip(self.context, testvip)
                # First, assert that create_resource was called once
                # with expected params.
                self.create_resource_mock.assert_called_once_with(
                    None,
                    netscaler_driver.VIPS_RESOURCE,
                    netscaler_driver.VIP_RESOURCE,
                    expectedvip)
                #Finally, assert that the vip object is now ACTIVE
                self.mock_update_status_obj.assert_called_once_with(
                    mock.ANY,
                    loadbalancer_db.Vip,
                    expectedvip['id'],
                    constants.ACTIVE)

    def test_create_vip_without_connection(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                testvip = self._build_testvip_contents(subnet['subnet'],
                                                       pool['pool'])
                expectedvip = self._build_expectedvip_contents(
                    testvip,
                    subnet['subnet'])
                errorcode = ncc_client.NCCException.CONNECTION_ERROR
                self.create_resource_mock.side_effect = (
                    ncc_client.NCCException(errorcode))
                # mock the plugin's update_status()
                self._mock_update_status()
                # reset the create_resource() mock
                self.create_resource_mock.reset_mock()
                # execute the method under test.
                self.driver.create_vip(self.context, testvip)
                # First, assert that update_resource was called once
                # with expected params.
                self.create_resource_mock.assert_called_once_with(
                    None,
                    netscaler_driver.VIPS_RESOURCE,
                    netscaler_driver.VIP_RESOURCE,
                    expectedvip)
                #Finally, assert that the vip object is in ERROR state
                self.mock_update_status_obj.assert_called_once_with(
                    mock.ANY,
                    loadbalancer_db.Vip,
                    testvip['id'],
                    constants.ERROR)

    def test_update_vip(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                with self.vip(pool=pool, subnet=subnet) as vip:
                    updated_vip = self._build_updated_testvip_contents(
                        vip['vip'],
                        subnet['subnet'],
                        pool['pool'])
                    expectedvip = self._build_updated_expectedvip_contents(
                        updated_vip,
                        subnet['subnet'],
                        pool['pool'])
                    # mock the plugin's update_status()
                    self._mock_update_status()
                    # reset the update_resource() mock
                    self.update_resource_mock.reset_mock()
                    # execute the method under test
                    self.driver.update_vip(self.context, updated_vip,
                                           updated_vip)
                    vip_resource_path = "%s/%s" % (
                        (netscaler_driver.VIPS_RESOURCE,
                         vip['vip']['id']))
                    # First, assert that update_resource was called once
                    # with expected params.
                    (self.update_resource_mock
                         .assert_called_once_with(
                             None,
                             vip_resource_path,
                             netscaler_driver.VIP_RESOURCE,
                             expectedvip))
                    #Finally, assert that the vip object is now ACTIVE
                    self.mock_update_status_obj.assert_called_once_with(
                        mock.ANY,
                        loadbalancer_db.Vip,
                        vip['vip']['id'],
                        constants.ACTIVE)

    def test_delete_vip(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                with contextlib.nested(
                    self.vip(pool=pool, subnet=subnet),
                    mock.patch.object(self.driver.plugin, '_delete_db_vip')
                ) as (vip, mock_delete_db_vip):
                    mock_delete_db_vip.return_value = None
                    #reset the remove_resource() mock
                    self.remove_resource_mock.reset_mock()
                    # execute the method under test
                    self.driver.delete_vip(self.context, vip['vip'])
                    vip_resource_path = "%s/%s" % (
                                        (netscaler_driver.VIPS_RESOURCE,
                                         vip['vip']['id']))
                    # Assert that remove_resource() was called once
                    # with expected params.
                    (self.remove_resource_mock
                         .assert_called_once_with(None, vip_resource_path))

    def test_create_pool(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet'),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_ports'),
            mock.patch.object(self.driver.plugin._core_plugin, 'create_port')
        ) as (subnet, mock_get_subnet, mock_get_ports, mock_create_port):
            mock_get_subnet.return_value = subnet['subnet']
            mock_get_ports.return_value = None
            mock_create_port.return_value = TESTPOOL_SNAT_PORT
            testpool = self._build_testpool_contents(subnet['subnet'])
            expectedpool = self._build_expectedpool_contents(testpool,
                                                             subnet['subnet'])
            #reset the create_resource() mock
            self.create_resource_mock.reset_mock()
            # mock the plugin's update_status()
            self._mock_update_status()
            # execute the method under test
            self.driver.create_pool(self.context, testpool)
            # First, assert that create_resource was called once
            # with expected params.
            (self.create_resource_mock
                 .assert_called_once_with(None,
                                          netscaler_driver.POOLS_RESOURCE,
                                          netscaler_driver.POOL_RESOURCE,
                                          expectedpool))
            #Finally, assert that the pool object is now ACTIVE
            self.mock_update_status_obj.assert_called_once_with(
                mock.ANY,
                loadbalancer_db.Pool,
                expectedpool['id'],
                constants.ACTIVE)

    def test_create_pool_with_error(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet'),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_ports'),
            mock.patch.object(self.driver.plugin._core_plugin, 'create_port')
        ) as (subnet, mock_get_subnet, mock_get_ports, mock_create_port):
            mock_get_subnet.return_value = subnet['subnet']
            mock_get_ports.return_value = None
            mock_create_port.return_value = TESTPOOL_SNAT_PORT
            errorcode = ncc_client.NCCException.CONNECTION_ERROR
            self.create_resource_mock.side_effect = (ncc_client
                                                     .NCCException(errorcode))
            testpool = self._build_testpool_contents(subnet['subnet'])
            expectedpool = self._build_expectedpool_contents(testpool,
                                                             subnet['subnet'])
            # mock the plugin's update_status()
            self._mock_update_status()
            #reset the create_resource() mock
            self.create_resource_mock.reset_mock()
            # execute the method under test.
            self.driver.create_pool(self.context, testpool)
            # Also assert that create_resource was called once
            # with expected params.
            (self.create_resource_mock
                 .assert_called_once_with(None,
                                          netscaler_driver.POOLS_RESOURCE,
                                          netscaler_driver.POOL_RESOURCE,
                                          expectedpool))
            #Finally, assert that the pool object is in ERROR state
            self.mock_update_status_obj.assert_called_once_with(
                mock.ANY,
                loadbalancer_db.Pool,
                expectedpool['id'],
                constants.ERROR)

    def test_create_pool_with_snatportcreate_failure(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet'),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_ports'),
            mock.patch.object(self.driver.plugin._core_plugin, 'create_port')
        ) as (subnet, mock_get_subnet, mock_get_ports, mock_create_port):
            mock_get_subnet.return_value = subnet['subnet']
            mock_get_ports.return_value = None
            mock_create_port.side_effect = exceptions.NeutronException()
            testpool = self._build_testpool_contents(subnet['subnet'])
            #reset the create_resource() mock
            self.create_resource_mock.reset_mock()
            # execute the method under test.
            self.assertRaises(exceptions.NeutronException,
                              self.driver.create_pool,
                              self.context, testpool)

    def test_update_pool(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                updated_pool = self._build_updated_testpool_contents(
                    pool['pool'],
                    subnet['subnet'])
                expectedpool = self._build_updated_expectedpool_contents(
                    updated_pool,
                    subnet['subnet'])
                # mock the plugin's update_status()
                self._mock_update_status()
                # reset the update_resource() mock
                self.update_resource_mock.reset_mock()
                # execute the method under test.
                self.driver.update_pool(self.context, pool['pool'],
                                        updated_pool)
                pool_resource_path = "%s/%s" % (
                    (netscaler_driver.POOLS_RESOURCE,
                     pool['pool']['id']))
                # First, assert that update_resource was called once
                # with expected params.
                (self.update_resource_mock
                     .assert_called_once_with(None,
                                              pool_resource_path,
                                              netscaler_driver.POOL_RESOURCE,
                                              expectedpool))
                #Finally, assert that the pool object is now ACTIVE
                self.mock_update_status_obj.assert_called_once_with(
                    mock.ANY,
                    loadbalancer_db.Pool,
                    pool['pool']['id'],
                    constants.ACTIVE)

    def test_delete_pool(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with contextlib.nested(
                self.pool(provider=LBAAS_PROVIDER_NAME),
                mock.patch.object(self.driver.plugin._core_plugin,
                                  'delete_port'),
                mock.patch.object(self.driver.plugin._core_plugin,
                                  'get_ports'),
                mock.patch.object(self.driver.plugin,
                                  'get_pools'),
                mock.patch.object(self.driver.plugin,
                                  '_delete_db_pool')
            ) as (pool, mock_delete_port, mock_get_ports, mock_get_pools,
                  mock_delete_db_pool):
                mock_delete_port.return_value = None
                mock_get_ports.return_value = [{'id': TESTPOOL_PORT_ID}]
                mock_get_pools.return_value = []
                mock_delete_db_pool.return_value = None
                #reset the remove_resource() mock
                self.remove_resource_mock.reset_mock()
                # execute the method under test.
                self.driver.delete_pool(self.context, pool['pool'])
                pool_resource_path = "%s/%s" % (
                    (netscaler_driver.POOLS_RESOURCE,
                     pool['pool']['id']))
                # Assert that delete_resource was called
                # once with expected params.
                (self.remove_resource_mock
                     .assert_called_once_with(None, pool_resource_path))

    def test_create_member(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin,
                              'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                testmember = self._build_testmember_contents(pool['pool'])
                expectedmember = self._build_expectedmember_contents(
                    testmember)
                # mock the plugin's update_status()
                self._mock_update_status()
                #reset the create_resource() mock
                self.create_resource_mock.reset_mock()
                # execute the method under test.
                self.driver.create_member(self.context, testmember)
                # First, assert that create_resource was called once
                # with expected params.
                (self.create_resource_mock
                     .assert_called_once_with(
                         None,
                         netscaler_driver.POOLMEMBERS_RESOURCE,
                         netscaler_driver.POOLMEMBER_RESOURCE,
                         expectedmember))
                #Finally, assert that the member object is now ACTIVE
                self.mock_update_status_obj.assert_called_once_with(
                    mock.ANY,
                    loadbalancer_db.Member,
                    expectedmember['id'],
                    constants.ACTIVE)

    def test_update_member(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                with self.member(pool_id=pool['pool']['id']) as member:
                    updatedmember = (self._build_updated_testmember_contents(
                        member['member']))
                    expectedmember = (self
                                      ._build_updated_expectedmember_contents(
                                          updatedmember))
                    # mock the plugin's update_status()
                    self._mock_update_status()
                    # reset the update_resource() mock
                    self.update_resource_mock.reset_mock()
                    # execute the method under test
                    self.driver.update_member(self.context,
                                              member['member'],
                                              updatedmember)
                    member_resource_path = "%s/%s" % (
                        (netscaler_driver.POOLMEMBERS_RESOURCE,
                         member['member']['id']))
                    # First, assert that update_resource was called once
                    # with expected params.
                    (self.update_resource_mock
                         .assert_called_once_with(
                             None,
                             member_resource_path,
                             netscaler_driver.POOLMEMBER_RESOURCE,
                             expectedmember))
                    #Finally, assert that the member object is now ACTIVE
                    self.mock_update_status_obj.assert_called_once_with(
                        mock.ANY,
                        loadbalancer_db.Member,
                        member['member']['id'],
                        constants.ACTIVE)

    def test_delete_member(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                with contextlib.nested(
                    self.member(pool_id=pool['pool']['id']),
                    mock.patch.object(self.driver.plugin, '_delete_db_member')
                ) as (member, mock_delete_db_member):
                    mock_delete_db_member.return_value = None
                    # reset the remove_resource() mock
                    self.remove_resource_mock.reset_mock()
                    # execute the method under test
                    self.driver.delete_member(self.context,
                                              member['member'])
                    member_resource_path = "%s/%s" % (
                        (netscaler_driver.POOLMEMBERS_RESOURCE,
                         member['member']['id']))
                    # Assert that delete_resource was called once
                    # with expected params.
                    (self.remove_resource_mock
                         .assert_called_once_with(None, member_resource_path))

    def test_create_pool_health_monitor(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                testhealthmonitor = self._build_testhealthmonitor_contents(
                    pool['pool'])
                expectedhealthmonitor = (
                    self._build_expectedhealthmonitor_contents(
                        testhealthmonitor))
                with mock.patch.object(self.driver.plugin,
                                       'update_pool_health_monitor') as mhm:
                    # reset the create_resource() mock
                    self.create_resource_mock.reset_mock()
                    # execute the method under test.
                    self.driver.create_pool_health_monitor(self.context,
                                                           testhealthmonitor,
                                                           pool['pool']['id'])
                    # First, assert that create_resource was called once
                    # with expected params.
                    resource_path = "%s/%s/%s" % (
                        netscaler_driver.POOLS_RESOURCE,
                        pool['pool']['id'],
                        netscaler_driver.MONITORS_RESOURCE)
                    (self.create_resource_mock
                         .assert_called_once_with(
                             None,
                             resource_path,
                             netscaler_driver.MONITOR_RESOURCE,
                             expectedhealthmonitor))
                    # Finally, assert that the healthmonitor object is
                    # now ACTIVE.
                    (mhm.assert_called_once_with(
                        mock.ANY,
                        expectedhealthmonitor['id'],
                        pool['pool']['id'],
                        constants.ACTIVE, ""))

    def test_update_pool_health_monitor(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                with self.health_monitor(
                    pool_id=pool['pool']['id']
                ) as (health_monitor):
                    updatedhealthmonitor = (
                        self._build_updated_testhealthmonitor_contents(
                            health_monitor['health_monitor']))
                    expectedhealthmonitor = (
                        self._build_updated_expectedhealthmonitor_contents(
                            updatedhealthmonitor))
                    with mock.patch.object(self.driver.plugin,
                                           'update_pool_health_monitor')as mhm:
                        # reset the update_resource() mock
                        self.update_resource_mock.reset_mock()
                        # execute the method under test.
                        self.driver.update_pool_health_monitor(
                            self.context,
                            health_monitor['health_monitor'],
                            updatedhealthmonitor,
                            pool['pool']['id'])
                        monitor_resource_path = "%s/%s" % (
                            (netscaler_driver.MONITORS_RESOURCE,
                             health_monitor['health_monitor']['id']))
                        # First, assert that update_resource was called once
                        # with expected params.
                        self.update_resource_mock.assert_called_once_with(
                            None,
                            monitor_resource_path,
                            netscaler_driver.MONITOR_RESOURCE,
                            expectedhealthmonitor)
                        #Finally, assert that the member object is now ACTIVE
                        (mhm.assert_called_once_with(
                            mock.ANY,
                            health_monitor['health_monitor']['id'],
                            pool['pool']['id'],
                            constants.ACTIVE, ""))

    def test_delete_pool_health_monitor(self):
        with contextlib.nested(
            self.subnet(),
            mock.patch.object(self.driver.plugin._core_plugin, 'get_subnet')
        ) as (subnet, mock_get_subnet):
            mock_get_subnet.return_value = subnet['subnet']
            with self.pool(provider=LBAAS_PROVIDER_NAME) as pool:
                with contextlib.nested(
                    self.health_monitor(pool_id=pool['pool']['id']),
                    mock.patch.object(self.driver.plugin,
                                      '_delete_db_pool_health_monitor')
                ) as (health_monitor, mock_delete_db_monitor):
                    mock_delete_db_monitor.return_value = None
                    # reset the remove_resource() mock
                    self.remove_resource_mock.reset_mock()
                    # execute the method under test.
                    self.driver.delete_pool_health_monitor(
                        self.context,
                        health_monitor['health_monitor'],
                        pool['pool']['id'])
                    monitor_resource_path = "%s/%s/%s/%s" % (
                        netscaler_driver.POOLS_RESOURCE,
                        pool['pool']['id'],
                        netscaler_driver.MONITORS_RESOURCE,
                        health_monitor['health_monitor']['id'])
                    # Assert that delete_resource was called once
                    # with expected params.
                    self.remove_resource_mock.assert_called_once_with(
                        None,
                        monitor_resource_path)

    def _build_testvip_contents(self, subnet, pool):
        vip_obj = dict(id=TESTVIP_ID,
                       name='testvip',
                       description='a test vip',
                       tenant_id=self._tenant_id,
                       subnet_id=subnet['id'],
                       address=TESTVIP_IP,
                       port_id=TESTVIP_PORT_ID,
                       pool_id=pool['id'],
                       protocol='HTTP',
                       protocol_port=80,
                       connection_limit=1000,
                       admin_state_up=True,
                       status='PENDING_CREATE',
                       status_description='')
        return vip_obj

    def _build_expectedvip_contents(self, testvip, subnet):
        expectedvip = dict(id=testvip['id'],
                           name=testvip['name'],
                           description=testvip['description'],
                           tenant_id=testvip['tenant_id'],
                           subnet_id=testvip['subnet_id'],
                           address=testvip['address'],
                           network_id=subnet['network_id'],
                           port_id=testvip['port_id'],
                           pool_id=testvip['pool_id'],
                           protocol=testvip['protocol'],
                           protocol_port=testvip['protocol_port'],
                           connection_limit=testvip['connection_limit'],
                           admin_state_up=testvip['admin_state_up'])
        return expectedvip

    def _build_updated_testvip_contents(self, testvip, subnet, pool):
        #update some updateable fields of the vip
        testvip['name'] = 'udpated testvip'
        testvip['description'] = 'An updated version of test vip'
        testvip['connection_limit'] = 2000
        return testvip

    def _build_updated_expectedvip_contents(self, testvip, subnet, pool):
        expectedvip = dict(name=testvip['name'],
                           description=testvip['description'],
                           connection_limit=testvip['connection_limit'],
                           admin_state_up=testvip['admin_state_up'],
                           pool_id=testvip['pool_id'])
        return expectedvip

    def _build_testpool_contents(self, subnet):
        pool_obj = dict(id=TESTPOOL_ID,
                        name='testpool',
                        description='a test pool',
                        tenant_id=self._tenant_id,
                        subnet_id=subnet['id'],
                        protocol='HTTP',
                        vip_id=None,
                        admin_state_up=True,
                        lb_method='ROUND_ROBIN',
                        status='PENDING_CREATE',
                        status_description='',
                        members=[],
                        health_monitors=[],
                        health_monitors_status=None,
                        provider=LBAAS_PROVIDER_NAME)
        return pool_obj

    def _build_expectedpool_contents(self, testpool, subnet):
        expectedpool = dict(id=testpool['id'],
                            name=testpool['name'],
                            description=testpool['description'],
                            tenant_id=testpool['tenant_id'],
                            subnet_id=testpool['subnet_id'],
                            network_id=subnet['network_id'],
                            protocol=testpool['protocol'],
                            vip_id=testpool['vip_id'],
                            lb_method=testpool['lb_method'],
                            snat_ip=TESTPOOL_SNATIP_ADDRESS,
                            port_id=TESTPOOL_PORT_ID,
                            admin_state_up=testpool['admin_state_up'])
        return expectedpool

    def _build_updated_testpool_contents(self, testpool, subnet):
        updated_pool = dict(testpool.items())
        updated_pool['name'] = 'udpated testpool'
        updated_pool['description'] = 'An updated version of test pool'
        updated_pool['lb_method'] = 'LEAST_CONNECTIONS'
        updated_pool['admin_state_up'] = True
        updated_pool['provider'] = LBAAS_PROVIDER_NAME
        updated_pool['status'] = 'PENDING_UPDATE'
        updated_pool['status_description'] = ''
        updated_pool['members'] = []
        updated_pool["health_monitors"] = []
        updated_pool["health_monitors_status"] = None
        return updated_pool

    def _build_updated_expectedpool_contents(self, testpool, subnet):
        expectedpool = dict(name=testpool['name'],
                            description=testpool['description'],
                            lb_method=testpool['lb_method'],
                            admin_state_up=testpool['admin_state_up'])
        return expectedpool

    def _build_testmember_contents(self, pool):
        member_obj = dict(
            id=TESTMEMBER_ID,
            tenant_id=self._tenant_id,
            pool_id=pool['id'],
            address=TESTMEMBER_IP,
            protocol_port=8080,
            weight=2,
            admin_state_up=True,
            status='PENDING_CREATE',
            status_description='')
        return member_obj

    def _build_expectedmember_contents(self, testmember):
        expectedmember = dict(
            id=testmember['id'],
            tenant_id=testmember['tenant_id'],
            pool_id=testmember['pool_id'],
            address=testmember['address'],
            protocol_port=testmember['protocol_port'],
            weight=testmember['weight'],
            admin_state_up=testmember['admin_state_up'])
        return expectedmember

    def _build_updated_testmember_contents(self, testmember):
        updated_member = dict(testmember.items())
        updated_member.update(
            weight=3,
            admin_state_up=True,
            status='PENDING_CREATE',
            status_description=''
        )
        return updated_member

    def _build_updated_expectedmember_contents(self, testmember):
        expectedmember = dict(weight=testmember['weight'],
                              pool_id=testmember['pool_id'],
                              admin_state_up=testmember['admin_state_up'])
        return expectedmember

    def _build_testhealthmonitor_contents(self, pool):
        monitor_obj = dict(
            id=TESTMONITOR_ID,
            tenant_id=self._tenant_id,
            type='TCP',
            delay=10,
            timeout=5,
            max_retries=3,
            admin_state_up=True,
            pools=[])
        pool_obj = dict(status='PENDING_CREATE',
                        status_description=None,
                        pool_id=pool['id'])
        monitor_obj['pools'].append(pool_obj)
        return monitor_obj

    def _build_expectedhealthmonitor_contents(self, testhealthmonitor):
        expectedmonitor = dict(id=testhealthmonitor['id'],
                               tenant_id=testhealthmonitor['tenant_id'],
                               type=testhealthmonitor['type'],
                               delay=testhealthmonitor['delay'],
                               timeout=testhealthmonitor['timeout'],
                               max_retries=testhealthmonitor['max_retries'],
                               admin_state_up=(
                                   testhealthmonitor['admin_state_up']))
        return expectedmonitor

    def _build_updated_testhealthmonitor_contents(self, testmonitor):
        updated_monitor = dict(testmonitor.items())
        updated_monitor.update(
            delay=30,
            timeout=3,
            max_retries=5,
            admin_state_up=True
        )
        return updated_monitor

    def _build_updated_expectedhealthmonitor_contents(self, testmonitor):
        expectedmonitor = dict(delay=testmonitor['delay'],
                               timeout=testmonitor['timeout'],
                               max_retries=testmonitor['max_retries'],
                               admin_state_up=testmonitor['admin_state_up'])
        return expectedmonitor

    def _mock_update_status(self):
        #patch the plugin's update_status() method with a mock object
        self.mock_update_status_patcher = mock.patch.object(
            self.driver.plugin,
            'update_status')
        self.mock_update_status_obj = self.mock_update_status_patcher.start()


def mock_create_resource_func(*args, **kwargs):
    return 201, {}


def mock_update_resource_func(*args, **kwargs):
    return 202, {}


def mock_retrieve_resource_func(*args, **kwargs):
    return 200, {}


def mock_remove_resource_func(*args, **kwargs):
    return 200, {}
