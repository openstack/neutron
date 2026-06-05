# Copyright 2026 Red Hat, LLC
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

from neutron.agent.linux import ip_lib
from neutron.agent.linux import svd as linux_svd
from neutron.agent.linux import utils as agent_utils
from neutron.common import utils
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron.tests.functional.agent.linux import base


class TestSvdFunctional(base.BaseNetlinkTestCase):

    DSTPORT = 15000
    LOCAL_IP = '10.10.10.10'
    MAC = 'aa:bb:cc:dd:ee:ff'
    SVI_MAC = '00:11:22:33:44:55'

    @staticmethod
    def _safe_delete(name):
        try:
            ip_lib.IPDevice(name).link.delete()
        except Exception:
            pass

    @staticmethod
    def _set_link_up(name):
        agent_utils.execute(
            ['ip', 'link', 'set', name, 'up'],
            run_as_root=True, privsep_exec=True)

    def setUp(self):
        super().setUp()
        self._br = utils.get_rand_name(15, 'brevpn-')
        self._vx = utils.get_rand_name(15, 'vxevpn-')
        self._svi_names = {}
        # VNIs are a system-global resource (vnifilter mode), so parallel
        # test workers must not share VNI values.  Derive a unique base
        # from the test method's position in the sorted method list.
        vni_methods = sorted(
            m for m in dir(self) if m.startswith('test_'))
        method_idx = vni_methods.index(self._testMethodName)
        self._base_vni = 5000 + method_idx * 10

        self._parent = utils.get_rand_name(15, 'svdp-')
        privileged.create_interface(self._parent, None, 'dummy')
        self._set_link_up(self._parent)
        ip_lib.IPDevice(self._parent).addr.add(self.LOCAL_IP + '/32')
        self.addCleanup(self._safe_delete, self._parent)

        self._vrf = utils.get_rand_name(15, 'svdr-')
        privileged.create_interface(self._vrf, None, 'vrf', vrf_table=9999)
        self._set_link_up(self._vrf)
        self.addCleanup(self._safe_delete, self._vrf)

    def _create_svd(self):
        brvxlan = linux_svd.Svd(br_evpn=self._br, vxlan_evpn=self._vx)
        brvxlan.create(local_ip=self.LOCAL_IP, mac=self.MAC,
                       vxlan_parent=self._parent, dstport=self.DSTPORT)
        self.addCleanup(self._safe_delete, self._vx)
        self.addCleanup(self._safe_delete, self._br)
        return brvxlan

    def _svi_name(self, vid):
        return self._svi_names.setdefault(vid, utils.get_rand_name(15, 'vl-'))

    def _vid(self, offset=0):
        return 100 + offset

    def _vni(self, offset=0):
        return self._base_vni + offset

    def _bridge_cmd(self, *args):
        return agent_utils.execute(
            ['bridge'] + list(args),
            run_as_root=True, privsep_exec=True)

    def test_create_svd(self):
        self._create_svd()

        self.assertTrue(ip_lib.device_exists(self._br))
        self.assertTrue(ip_lib.device_exists(self._vx))

        br_output = agent_utils.execute(
            ['ip', '-d', 'link', 'show', self._br],
            run_as_root=True, privsep_exec=True)
        self.assertIn('vlan_filtering 1', br_output)
        self.assertIn('vlan_default_pvid 0', br_output)
        self.assertIn('mtu 1500', br_output)
        self.assertIn('addrgenmode none', br_output)

        vx_output = agent_utils.execute(
            ['ip', '-d', 'link', 'show', self._vx],
            run_as_root=True, privsep_exec=True)
        self.assertIn('vnifilter', vx_output)
        self.assertIn('external', vx_output)
        self.assertIn('addrgenmode none', vx_output)

    def test_create_svd_parent_not_found(self):
        brvxlan = linux_svd.Svd(br_evpn=self._br, vxlan_evpn=self._vx)
        self.assertRaises(linux_svd.SvdNoVxlanParent, brvxlan.create,
                          local_ip=self.LOCAL_IP, mac=self.MAC,
                          vxlan_parent='no-such-dev',
                          dstport=self.DSTPORT)
        self.assertFalse(ip_lib.device_exists(self._br))
        self.assertFalse(ip_lib.device_exists(self._vx))

    def test_create_svd_device_exists(self):
        self._create_svd()
        brvxlan = linux_svd.Svd(br_evpn=self._br, vxlan_evpn=self._vx)
        self.assertRaises(linux_svd.SvdDeviceAlreadyExists, brvxlan.create,
                          local_ip=self.LOCAL_IP, mac=self.MAC,
                          vxlan_parent=self._parent,
                          dstport=self.DSTPORT)

    def test_delete_svd(self):
        svd = self._create_svd()

        svd.delete()

        self.assertFalse(ip_lib.device_exists(self._br))
        self.assertFalse(ip_lib.device_exists(self._vx))

    def test_delete_svd_not_found(self):
        brvxlan = linux_svd.Svd(br_evpn=self._br, vxlan_evpn=self._vx)
        self.assertRaises(linux_svd.SvdNotFound, brvxlan.delete)

    def test_add_vni(self):
        svd = self._create_svd()

        vni = self._vni()
        vid = self._vid()
        svi_name = self._svi_name(vid)
        svd.add_vni(svi_name, vni, vid, self._vrf, self.SVI_MAC)
        self.assertTrue(ip_lib.device_exists(svi_name))

        br_vlans = self._bridge_cmd('vlan', 'show', 'dev', self._br)
        self.assertRegex(br_vlans, r'\b%s\b' % vid)

        vx_vlans = self._bridge_cmd('vlan', 'show', 'dev', self._vx)
        self.assertRegex(vx_vlans, r'\b%s\b' % vid)

        vni_output = self._bridge_cmd('vni', 'show', 'dev', self._vx)
        self.assertIn(str(vni), vni_output)

    def test_add_vni_vrf_not_found(self):
        brvxlan = self._create_svd()
        vni = self._vni()
        vid = self._vid()
        svi_name = self._svi_name(vid)
        self.assertRaises(linux_svd.SvdDevsNotFound, brvxlan.add_vni,
                          svi_name, vni, vid, 'no-such-vrf', self.SVI_MAC)
        self.assertFalse(ip_lib.device_exists(svi_name))
        vni_output = self._bridge_cmd('vni', 'show', 'dev', self._vx)
        self.assertNotIn(str(vni), vni_output)

    def test_add_vni_netlink_error(self):
        svd = self._create_svd()
        vni = self._vni()
        vid = self._vid()
        svi_name = self._svi_name(vid)
        svd.add_vni(svi_name, vni, vid, self._vrf, self.SVI_MAC)
        self.addCleanup(svd.del_vni, svi_name, vni, vid)
        # Add the same VNI a second time to trigger NetlinkError
        self.assertRaises(linux_svd.SvdNetlinkError, svd.add_vni,
                          svi_name, vni, vid, self._vrf, self.SVI_MAC)

    def test_del_vni(self):
        svd = self._create_svd()
        vni = self._vni()
        vid = self._vid()
        svi_name = self._svi_name(vid)
        svd.add_vni(svi_name, vni, vid, self._vrf, self.SVI_MAC)

        svd.del_vni(svi_name, vni, vid)

        self.assertFalse(ip_lib.device_exists(svi_name))

        vni_output = self._bridge_cmd('vni', 'show', 'dev', self._vx)
        self.assertNotIn(str(vni), vni_output)

    def test_del_vni_svi_not_found(self):
        svd = self._create_svd()
        self.assertRaises(linux_svd.SvdSviNotFound, svd.del_vni,
                          self._svi_name(self._vid()), self._vni(),
                          self._vid())

    def test_add_multiple_vnis(self):
        svd = self._create_svd()

        vni1 = self._vni()
        vid1 = self._vid()
        vni2 = self._vni(1)
        vid2 = self._vid(1)
        svi_name1 = self._svi_name(vid1)
        svi_name2 = self._svi_name(vid2)
        svd.add_vni(svi_name1, vni1, vid1, self._vrf, self.SVI_MAC)
        svd.add_vni(svi_name2, vni2, vid2, self._vrf, self.SVI_MAC)

        self.assertTrue(ip_lib.device_exists(svi_name1))
        self.assertTrue(ip_lib.device_exists(svi_name2))

        vni_output = self._bridge_cmd('vni', 'show', 'dev', self._vx)
        self.assertIn(str(vni1), vni_output)
        self.assertIn(str(vni2), vni_output)

        svd.del_vni(svi_name1, vni1, vid1)
        self.assertFalse(ip_lib.device_exists(svi_name1))
        self.assertTrue(ip_lib.device_exists(svi_name2))

        svd.del_vni(svi_name2, vni2, vid2)

    def test_svi_attached_to_vrf(self):
        svd = self._create_svd()

        vni = self._vni()
        vid = self._vid()
        svi_name = self._svi_name(vid)
        svd.add_vni(svi_name, vni, vid, self._vrf, self.SVI_MAC)

        link_output = agent_utils.execute(
            ['ip', '-d', 'link', 'show', svi_name],
            run_as_root=True, privsep_exec=True)
        self.assertIn(self.SVI_MAC, link_output)
        self.assertIn('master %s' % self._vrf, link_output)
        self.assertIn('state UP', link_output)

        svd.del_vni(svi_name, vni, vid)
