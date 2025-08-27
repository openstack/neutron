# Copyright 2025 Red Hat, Inc.
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


from oslo_utils import uuidutils

from neutron.common import utils as common_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services.bgp import ovn as bgp_ovn
from neutron.tests.functional import base


class OvnNbIdlWithUniqueConnection(bgp_ovn.BgpOvnNbIdl):
    # because the ovsdb connection is a class attribute, we cannot have
    # two connections in the same process
    @property
    def ovsdb_connection(self):
        return self._ovsdb_connection

    @ovsdb_connection.setter
    def ovsdb_connection(self, value):
        self._ovsdb_connection = value


class OvnNbIdlTest(bgp_ovn.OvnNbIdl):
    api_cls = OvnNbIdlWithUniqueConnection


class TestOvnNbIdl(base.TestOVNFunctionalBase):
    """Test OvnNbIdl read-write operations."""

    def setUp(self):
        super().setUp()
        self.nb_connection = ovn_conf.get_ovn_nb_connection()
        self.nb_idl = bgp_ovn.OvnNbIdl(self.nb_connection)
        self.addCleanup(self._cleanup)
        self.nb_bgp_api = self.nb_idl.start(timeout=10)

    def _cleanup(self):
        if hasattr(self, 'nb_bgp_api') and self.nb_bgp_api:
            try:
                self.nb_bgp_api.ovsdb_connection.stop(timeout=5)
                self.nb_bgp_api.__class__._ovsdb_connection = None
            except Exception:
                pass

    def test_read_write_operations(self):
        """Test NB IDL read and write operations."""
        # Test write: create logical switch
        ls_name = f"test_ls_{uuidutils.generate_uuid()}"
        ls = self.nb_bgp_api.ls_add(ls_name).execute(check_error=True)
        self.assertEqual(ls.name, ls_name)

        # Test read: list logical switches
        ls_list = self.nb_bgp_api.ls_list().execute(check_error=True)
        ls_names = [switch.name for switch in ls_list]
        self.assertIn(ls_name, ls_names)

    def test_leader_only_is_true(self):
        self.assertTrue(self.nb_idl.leader_only)


class TestOvnSbIdl(base.TestOVNFunctionalBase):
    """Test OvnSbIdl read-write operations."""

    def setUp(self):
        super().setUp()
        self.sb_connection = ovn_conf.get_ovn_sb_connection()
        # Register Encap table too so we can create a chassis
        self.addCleanup(self._cleanup)
        bgp_ovn.OvnSbIdl.tables = ('Chassis', 'Encap')
        self.sb_idl = bgp_ovn.OvnSbIdl(self.sb_connection)
        self.sb_bgp_api = self.sb_idl.start(timeout=10)

    def _cleanup(self):
        if hasattr(self, 'sb_bgp_api') and self.sb_bgp_api:
            try:
                self.sb_bgp_api.ovsdb_connection.stop(timeout=5)
                self.sb_bgp_api.__class__._ovsdb_connection = None
            except Exception:
                pass
        bgp_ovn.OvnSbIdl.tables = bgp_ovn.OVN_SB_TABLES

    def test_read_write_operations(self):
        """Test SB IDL read and write operations."""
        # Test write: add chassis
        chassis_name = f"test_chassis_{uuidutils.generate_uuid()}"
        hostname = f"{chassis_name}.example.com"
        self.sb_bgp_api.chassis_add(
            chassis_name, ['geneve'], '192.168.1.100',
            hostname=hostname).execute(check_error=True)

        # Test read: list chassis
        chassis_list = self.sb_bgp_api.chassis_list().execute(check_error=True)
        self.assertIn(chassis_name, [chassis.name for chassis in chassis_list])
        self.assertEqual(len(chassis_list), 1)

    def test_leader_only_is_false(self):
        self.assertFalse(self.sb_idl.leader_only)


class TestBgpOvnLocking(base.TestOVNFunctionalBase):
    """Test BGP OVN locking mechanism."""

    def setUp(self):
        super().setUp()
        self.nb_connection = ovn_conf.get_ovn_nb_connection()
        self.addCleanup(self._cleanup)

        # Create two IDL instances to test locking
        self.nb_idl1 = OvnNbIdlTest(self.nb_connection)
        self.nb_bgp_api1 = self.nb_idl1.start(timeout=10)

        self.nb_idl2 = OvnNbIdlTest(self.nb_connection)
        self.nb_bgp_api2 = self.nb_idl2.start(timeout=10)


    def _cleanup(self):
        for api in [getattr(self, 'nb_bgp_api1', None),
                    getattr(self, 'nb_bgp_api2', None)]:
            if api:
                try:
                    api.ovsdb_connection.stop(timeout=5)
                except Exception:
                    pass

    def test_locking_mechanism(self):
        """Test BGP topology locking mechanism."""
        # No lock is active, both APIs should have access
        self.assertTrue(self.nb_bgp_api1.has_lock)
        self.assertTrue(self.nb_bgp_api2.has_lock)

        # First API acquires the lock
        self.nb_bgp_api1.set_lock()
        self.nb_bgp_api2.set_lock()

        # Second API should lose the lock
        common_utils.wait_until_true(
            lambda: not self.nb_bgp_api2.has_lock,
            timeout=5,
            exception=AssertionError("Second API did not lose the lock")
        )

        # First API should still have the lock
        self.assertTrue(self.nb_bgp_api1.has_lock)

        # Disconnect first API and check that second API can acquire the lock
        self.nb_bgp_api1.ovsdb_connection.stop(timeout=5)

        common_utils.wait_until_true(
            lambda: self.nb_bgp_api2.has_lock,
            timeout=5,
            exception=AssertionError("Second API did not acquire lock")
        )
