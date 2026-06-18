# Copyright 2026 Red Hat, Inc.
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

import platform
import unittest

from pyroute2.netlink import rtnl

from neutron.agent.linux.evpn_router.frr import exceptions as frr_exceptions
from neutron.agent.linux.evpn_router.frr import frr_driver
from neutron.agent.linux.evpn_router import interface
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import utils as common_utils
from neutron.conf.agent.ovn.evpn import config as evpn_conf
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron_lib import exceptions
from oslo_serialization import jsonutils


class FrrVtyshExecutorNamespaced(frr_driver.FrrVtyshExecutor):
    """Namespaced vtysh executor for testing.

    Do not add any logic here — this subclass exists only to run
    vtysh in a network namespace so that functional tests exercise
    the production FrrVtyshExecutor code paths unchanged.
    """

    def __init__(self, namespace):
        self._namespace = namespace

    @property
    def _vtysh_base_cmd(self) -> list[str]:
        return super()._vtysh_base_cmd + ['-N', self._namespace]


def _is_centos9_frr85():
    """Return True on CentOS 9 with FRR 8.5 (LP#2156642)."""
    try:
        info = platform.freedesktop_os_release()
    except OSError:
        return False
    if info.get('ID') != 'centos' or not info.get(
            'VERSION_ID', '').startswith('9'):
        return False
    try:
        executor = FrrVtyshExecutorNamespaced("")
        output = executor.execute_cli_cmd('show version json')
        frr_version = jsonutils.loads(output).get('version', '')
        return frr_version.startswith('8.5')
    except Exception:
        return False


class NamespacedVRFHandler(interface.EVPNRouterVrfHandler):
    """VRF handler that creates VRFs and required linux interfaces for
       a FRR service.
    """
    # TODO(mtomaska): Replace subprocess ip commands with ip_lib (pyroute2).
    # ip_lib already supports: device exists, create/delete interface,
    # set up/down, set master, add IP address, create VXLAN.
    # Missing from ip_lib: addrgenmode, bridge_slave neigh_suppress/learning,
    # VXLAN nolearning.
    # For now, to avoid mixing two different approaches, all operations
    # use subprocess ip commands.

    def __init__(self, namespace, vtep_ip=None, dstport=4789):
        self._namespace = namespace
        self._vtep_ip = vtep_ip
        self._dstport = dstport

    def _ns_exec(self, cmd, **kwargs):
        return linux_utils.execute(
            ['ip', 'netns', 'exec', self._namespace] + cmd,
            run_as_root=True, **kwargs)

    def _vni(self, vrf_name):
        return int(vrf_name.split('-')[-1])

    def _bridge_name(self, vni):
        return 'br-%d' % vni

    def _vxlan_name(self, vni):
        return 'vxlan-%d' % vni

    def _device_exists(self, dev_name):
        _out, std_err = self._ns_exec(
            ['ip', 'link', 'show', dev_name],
            check_exit_code=False,
            return_stderr=True,
            log_fail_as_error=False)
        return not str(std_err).strip()

    def _delete_device(self, dev_name, step):
        try:
            _out, std_err = self._ns_exec(
                ['ip', 'link', 'del', dev_name],
                check_exit_code=False,
                return_stderr=True,
                log_fail_as_error=False)
        except exceptions.ProcessExecutionError as err:
            raise frr_exceptions.FrrVrfError(
                "Failed to delete %s" % dev_name,
                step=step,
                cause=err,
            ) from err
        std_err = str(std_err).strip()
        ok = std_err in ('', 'Cannot find device "%s"' % dev_name)
        if not ok:
            raise frr_exceptions.FrrVrfError(
                "Failed to delete %s: %s" % (dev_name, std_err),
                step=step,
            )

    def _ensure_vrf_created(self, vrf_name):
        if self._device_exists(vrf_name):
            return

        # NOTE: For simplicity, the routing table ID is the same as the VNI
        table_id = self._vni(vrf_name)
        try:
            self._ns_exec(
                ['ip', 'link', 'add', vrf_name,
                 'type', 'vrf', 'table', str(table_id)])
            self._ns_exec(
                ['ip', 'link', 'set', vrf_name, 'up'])
        except exceptions.ProcessExecutionError as err:
            raise frr_exceptions.FrrVrfError(
                "Failed to create VRF: %s" % vrf_name,
                step='ensure_vrf_exists',
                cause=err,
            ) from err

    def _ensure_bridge_created(self, vrf_name):
        vni = self._vni(vrf_name)
        br_name = self._bridge_name(vni)
        if self._device_exists(br_name):
            return

        try:
            self._ns_exec(
                ['ip', 'link', 'add', br_name, 'type', 'bridge'])
            self._ns_exec(
                ['ip', 'link', 'set', br_name,
                 'master', vrf_name, 'addrgenmode', 'none'])
            self._ns_exec(
                ['ip', 'link', 'set', br_name, 'up'])
        except exceptions.ProcessExecutionError as err:
            raise frr_exceptions.FrrVrfError(
                "Failed to create bridge: %s" % br_name,
                step='ensure_bridge_exists',
                cause=err,
            ) from err

    def _ensure_vxlan_created(self, vrf_name):
        vni = self._vni(vrf_name)
        vxlan_name = self._vxlan_name(vni)
        br_name = self._bridge_name(vni)
        if self._device_exists(vxlan_name):
            return

        try:
            self._ns_exec(
                ['ip', 'link', 'add', vxlan_name,
                 'type', 'vxlan', 'local', self._vtep_ip,
                 'dstport', str(self._dstport),
                 'id', str(vni), 'nolearning'])
            self._ns_exec(
                ['ip', 'link', 'set', vxlan_name,
                 'master', br_name, 'addrgenmode', 'none'])
            self._ns_exec(
                ['ip', 'link', 'set', vxlan_name,
                 'type', 'bridge_slave',
                 'neigh_suppress', 'on', 'learning', 'off'])
            self._ns_exec(
                ['ip', 'link', 'set', vxlan_name, 'up'])
        except exceptions.ProcessExecutionError as err:
            raise frr_exceptions.FrrVrfError(
                "Failed to create VXLAN: %s" % vxlan_name,
                step='ensure_vxlan_exists',
                cause=err,
            ) from err

    def _set_vtep_ip_on_lo(self):
        out = self._ns_exec(
            ['ip', 'addr', 'show', 'dev', 'lo'])
        if self._vtep_ip in str(out):
            return
        try:
            self._ns_exec(
                ['ip', 'addr', 'add', '%s/32' % self._vtep_ip, 'dev', 'lo'])
        except exceptions.ProcessExecutionError as err:
            raise frr_exceptions.FrrVrfError(
                "Failed to set VTEP IP on lo",
                step='set_vtep_ip_on_lo',
                cause=err,
            ) from err

    def ensure_vrf_exists(self, vrf_name):
        self._ensure_vrf_created(vrf_name)
        if self._vtep_ip:
            self._set_vtep_ip_on_lo()
            self._ensure_bridge_created(vrf_name)
            self._ensure_vxlan_created(vrf_name)

    def ensure_vrf_deleted(self, vrf_name):
        if self._vtep_ip:
            vni = self._vni(vrf_name)
            self._delete_device(
                self._vxlan_name(vni), step='ensure_vxlan_deleted')
            self._delete_device(
                self._bridge_name(vni), step='ensure_bridge_deleted')
        self._delete_device(vrf_name, step='ensure_vrf_deleted')


def make_evpn_config(vni, bgp_router_id='10.0.0.1', vrf_name_prefix='vrf-'):
    return interface.EVPNRouterConfig(
        asn=65000,
        bgp_router_id=bgp_router_id,
        vrf_name=vrf_name_prefix + str(vni),
        vni=vni,
    )


def add_blackhole_routes(namespace, cidrs, table_id):
    """Add blackhole routes to simulate ovn-controller route advertisment."""
    for cidr in cidrs:
        ip_lib.add_ip_route(namespace, cidr, table=table_id,
                            type=rtnl.rt_type['blackhole'], scope=0)


def assert_routes(namespace, table_id, present=None, absent=None,
                  ip_version=4, timeout=5):
    def _check():
        routes = ip_lib.list_ip_routes(namespace, ip_version, table=table_id)
        found = {r['cidr'] for r in routes}
        if present and not present.issubset(found):
            return False
        if absent and absent.intersection(found):
            return False
        return True

    details = []
    if present:
        details.append("expected present: %s" % present)
    if absent:
        details.append("expected absent: %s" % absent)
    common_utils.wait_until_true(
        _check, timeout=timeout, sleep=1,
        exception=RuntimeError(
            "Routes did not converge in VRF table %s (%s)"
            % (table_id, ', '.join(details))))


class TestFrrVtyshDriverConfiguration(base.BaseSudoTestCase):

    def setUp(self):
        super().setUp()
        evpn_conf.register_opts()
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        self.frr_fixture = self.useFixture(
            net_helpers.FrrFixture(namespace=self.namespace))

        vrf_handler = NamespacedVRFHandler(self.namespace)
        executor = FrrVtyshExecutorNamespaced(self.namespace)
        self.driver = frr_driver.FrrVtyshDriver(
            vrf_handler=vrf_handler,
            peer_interface='lo',
            executor=executor)

    def _vrf_exists(self, vrf_name):
        return ip_lib.IPDevice(vrf_name, namespace=self.namespace).exists()

    def _get_running_config(self):
        return self.driver.executor.execute_cli_cmd(
            'show running-config')

    def test_create_evpn_router(self):
        config = make_evpn_config(vni=100)
        self.driver.create_evpn_router(config)

        running_config = self._get_running_config()
        self.assertIn('router bgp 65000', running_config)
        self.assertIn('bgp router-id 10.0.0.1', running_config)
        self.assertIn('router bgp 65000 vrf vrf-100', running_config)
        self.assertIn('vni 100', running_config)

    def test_delete_evpn_router(self):
        config = make_evpn_config(vni=100)
        self.driver.create_evpn_router(config)
        self.driver.delete_evpn_router(config)

        running_config = self._get_running_config()
        self.assertNotIn('router bgp 65000 vrf vrf-100', running_config)
        self.assertNotIn('vni 100', running_config)

    def test_create_three_delete_one_two_remain(self):
        configs = [make_evpn_config(vni) for vni in (100, 200, 300)]
        for config in configs:
            self.driver.create_evpn_router(config)

        self.driver.delete_evpn_router(configs[1])

        self.assertTrue(self._vrf_exists('vrf-100'))
        self.assertFalse(self._vrf_exists('vrf-200'))
        self.assertTrue(self._vrf_exists('vrf-300'))

        running_config = self._get_running_config()
        self.assertIn('router bgp 65000 vrf vrf-100', running_config)
        self.assertNotIn('router bgp 65000 vrf vrf-200', running_config)
        self.assertIn('router bgp 65000 vrf vrf-300', running_config)

    def test_create_multiple_then_delete_all(self):
        configs = [make_evpn_config(vni) for vni in (100, 200, 300)]
        for config in configs:
            self.driver.create_evpn_router(config)
        for config in configs:
            self.driver.delete_evpn_router(config)

        running_config = self._get_running_config()
        self.assertNotIn('router bgp 65000 vrf vrf-100', running_config)
        self.assertNotIn('router bgp 65000 vrf vrf-200', running_config)
        self.assertNotIn('router bgp 65000 vrf vrf-300', running_config)

    def test_create_evpn_router_idempotent(self):
        config = make_evpn_config(vni=100)
        self.driver.create_evpn_router(config)
        self.driver.create_evpn_router(config)

        running_config = self._get_running_config()
        self.assertIn('router bgp 65000', running_config)
        self.assertIn('router bgp 65000 vrf vrf-100', running_config)
        self.assertIn('vni 100', running_config)

    def test_running_config_persist_on_reboot(self):
        config = make_evpn_config(vni=100)
        self.driver.create_evpn_router(config)

        self.frr_fixture.restart_frr()

        running_config = self._get_running_config()
        self.assertIn('router bgp 65000', running_config)
        self.assertIn('bgp router-id 10.0.0.1', running_config)
        self.assertIn('router bgp 65000 vrf vrf-100', running_config)
        self.assertIn('vni 100', running_config)

    def test_delete_noexisting_router_raises(self):
        config = make_evpn_config(vni=101)

        self.assertRaises(
            frr_exceptions.FrrApplyError,
            self.driver.delete_evpn_router, config)


class TestFrrVtyshDriverOperation(base.BaseSudoTestCase):
    """Functional tests for FRR EVPN router operation between two peers.

    Topology::

        Namespace A              Bridge NS            Namespace B
        +----------------+     +-----------+     +----------------+
        |  FRR (bgpd)    |     |           |     |  FRR (bgpd)    |
        |                |     |           |     |                |
        |  port_a -------+-----+- bridge --+-----+- port_b        |
        |  (link-local)  |veth |           |veth |  (link-local)  |
        +----------------+     +-----------+     +----------------+
    """

    def setUp(self):
        super().setUp()
        evpn_conf.register_opts()

        self.vtep_ip_a = '10.0.0.1'
        self.vtep_ip_b = '10.0.0.2'

        self.ns_a = self.useFixture(
            net_helpers.NamespaceFixture('frr-a-')).name
        self.frr_fixture_a = self.useFixture(
            net_helpers.FrrFixture(namespace=self.ns_a))

        self.ns_b = self.useFixture(
            net_helpers.NamespaceFixture('frr-b-')).name
        self.useFixture(net_helpers.FrrFixture(namespace=self.ns_b))

        bridge_fixture = self.useFixture(net_helpers.LinuxBridgeFixture())
        bridge = bridge_fixture.bridge

        self.port_a = self.useFixture(
            net_helpers.LinuxBridgePortFixture(
                bridge=bridge, namespace=self.ns_a)).port

        self.port_b = self.useFixture(
            net_helpers.LinuxBridgePortFixture(bridge, self.ns_b)).port

        vrf_handler_a = NamespacedVRFHandler(namespace=self.ns_a,
                                             vtep_ip=self.vtep_ip_a)
        executor_a = FrrVtyshExecutorNamespaced(self.ns_a)
        self.driver_a = frr_driver.FrrVtyshDriver(
            vrf_handler=vrf_handler_a,
            peer_interface=self.port_a.name,
            executor=executor_a)

        vrf_handler_b = NamespacedVRFHandler(namespace=self.ns_b,
                                             vtep_ip=self.vtep_ip_b)
        executor_b = FrrVtyshExecutorNamespaced(self.ns_b)
        self.driver_b = frr_driver.FrrVtyshDriver(
            vrf_handler=vrf_handler_b,
            peer_interface=self.port_b.name,
            executor=executor_b)

        # NOTE: Interfaces used for BGP instances must be reachable,
        # otherwise nothing will work.
        self._assert_ports_reachable()

    def _assert_ports_reachable(self):
        lladdr_b = ip_lib.get_ipv6_lladdr(
            self.port_b.link.address).split('/')[0]
        lladdr_a = ip_lib.get_ipv6_lladdr(
            self.port_a.link.address).split('/')[0]
        net_helpers.assert_ping(
            self.ns_a, lladdr_b, device=self.port_a.name)
        net_helpers.assert_ping(
            self.ns_b, lladdr_a, device=self.port_b.name)

    def test_routes_get_advertised(self):
        vni = 10
        advertised_routes_v4 = {'11.1.1.1/32', '12.1.1.0/32'}
        advertised_routes_v6 = {'fd00::1/128', 'fd00:1::/64'}
        conf_a = make_evpn_config(vni=vni, bgp_router_id=self.vtep_ip_a)
        conf_b = make_evpn_config(vni=vni, bgp_router_id=self.vtep_ip_b)

        self.driver_a.create_evpn_router(conf_a)
        self.driver_b.create_evpn_router(conf_b)

        add_blackhole_routes(
            self.ns_a, advertised_routes_v4, table_id=vni)
        add_blackhole_routes(
            self.ns_a, advertised_routes_v6, table_id=vni)

        assert_routes(self.ns_b, table_id=vni, present=advertised_routes_v4)
        assert_routes(self.ns_b, table_id=vni, present=advertised_routes_v6,
                      ip_version=6)

    @unittest.skipIf(_is_centos9_frr85(),
                     'CentOS 9 with FRR 8.5 VRF deletion bug LP#2156642')
    def test_multiple_routers_then_delete_one(self):
        vni_1 = 10
        vni_2 = 20
        route_1 = {'11.1.1.1/32'}
        route_2 = {'12.1.1.1/32'}

        conf_a1 = make_evpn_config(vni=vni_1, bgp_router_id=self.vtep_ip_a)
        conf_a2 = make_evpn_config(vni=vni_2, bgp_router_id=self.vtep_ip_a)
        conf_b1 = make_evpn_config(vni=vni_1, bgp_router_id=self.vtep_ip_b)
        conf_b2 = make_evpn_config(vni=vni_2, bgp_router_id=self.vtep_ip_b)

        self.driver_a.create_evpn_router(conf_a1)
        self.driver_a.create_evpn_router(conf_a2)
        self.driver_b.create_evpn_router(conf_b1)
        self.driver_b.create_evpn_router(conf_b2)

        add_blackhole_routes(
            self.ns_a, route_1, table_id=vni_1)
        add_blackhole_routes(
            self.ns_a, route_2, table_id=vni_2)

        assert_routes(self.ns_b, table_id=vni_1, present=route_1)
        assert_routes(self.ns_b, table_id=vni_2, present=route_2)

        self.driver_a.delete_evpn_router(conf_a1)

        assert_routes(self.ns_b, table_id=vni_1, absent=route_1)
        assert_routes(self.ns_b, table_id=vni_2, present=route_2)

    def test_routes_persist_after_restart(self):
        vni = 10
        advertised_routes = {'11.1.1.1/32', '12.1.1.0/32'}
        conf_a = make_evpn_config(vni=vni, bgp_router_id=self.vtep_ip_a)
        conf_b = make_evpn_config(vni=vni, bgp_router_id=self.vtep_ip_b)

        self.driver_a.create_evpn_router(conf_a)
        self.driver_b.create_evpn_router(conf_b)

        add_blackhole_routes(
            self.ns_a, advertised_routes, table_id=vni)
        assert_routes(self.ns_b, table_id=vni, present=advertised_routes)

        self.frr_fixture_a.restart_frr()

        assert_routes(self.ns_b, table_id=vni, present=advertised_routes)

    def test_routes_withdrawn_on_stop_and_restored_on_start(self):
        vni = 123
        advertised_routes = {'10.0.1.1/32', '12.2.1.1/32'}
        conf_a = make_evpn_config(vni=vni, bgp_router_id=self.vtep_ip_a)
        conf_b = make_evpn_config(vni=vni, bgp_router_id=self.vtep_ip_b)

        self.driver_a.create_evpn_router(conf_a)
        self.driver_b.create_evpn_router(conf_b)

        add_blackhole_routes(
            self.ns_a, advertised_routes, table_id=vni)
        assert_routes(self.ns_b, table_id=vni, present=advertised_routes)

        self.frr_fixture_a.stop_frr()

        assert_routes(self.ns_b, table_id=vni, absent=advertised_routes)

        self.frr_fixture_a.start_frr()

        assert_routes(self.ns_b, table_id=vni, present=advertised_routes)
