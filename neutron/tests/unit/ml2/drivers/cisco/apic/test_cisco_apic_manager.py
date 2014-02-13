# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

import mock
from webob import exc as wexc

from neutron.openstack.common import uuidutils

from neutron.plugins.ml2.drivers.cisco.apic import apic_manager
from neutron.plugins.ml2.drivers.cisco.apic import exceptions as cexc
from neutron.tests import base
from neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)


class TestCiscoApicManager(base.BaseTestCase,
                           mocked.ControllerMixin,
                           mocked.ConfigMixin,
                           mocked.DbModelMixin):

    def setUp(self):
        super(TestCiscoApicManager, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        mocked.DbModelMixin.set_up_mocks(self)

        self.mock_apic_manager_login_responses()
        self.mgr = apic_manager.APICManager()
        self.session = self.mgr.apic.session
        self.assert_responses_drained()
        self.reset_reponses()

    def test_mgr_session_login(self):
        login = self.mgr.apic.authentication
        self.assertEqual(login['userName'], mocked.APIC_USR)

    def test_mgr_session_logout(self):
        self.mock_response_for_post('aaaLogout')
        self.mgr.apic.logout()
        self.assert_responses_drained()
        self.assertIsNone(self.mgr.apic.authentication)

    def test_to_range(self):
        port_list = [4, 2, 3, 1, 7, 8, 10, 20, 6, 22, 21]
        expected_ranges = [(1, 4), (6, 8), (10, 10), (20, 22)]
        port_ranges = [r for r in apic_manager.group_by_ranges(port_list)]
        self.assertEqual(port_ranges, expected_ranges)

    def test_get_profiles(self):
        self.mock_db_query_filterby_first_return('faked')
        self.assertEqual(
            self.mgr.db.get_port_profile_for_node('node'),
            'faked'
        )
        self.assertEqual(
            self.mgr.db.get_profile_for_module('node', 'prof', 'module'),
            'faked'
        )
        self.assertEqual(
            self.mgr.db.get_profile_for_module_and_ports(
                'node', 'prof', 'module', 'from', 'to'
            ),
            'faked'
        )

    def test_add_profile(self):
        self.mgr.db.add_profile_for_module_and_ports(
            'node', 'prof', 'hpselc', 'module', 'from', 'to')
        self.assertTrue(self.mocked_session.add.called)
        self.assertTrue(self.mocked_session.flush.called)

    def test_ensure_port_profile_created(self):
        port_name = mocked.APIC_PORT
        self.mock_responses_for_create('infraAccPortP')
        self.mock_response_for_get('infraAccPortP', name=port_name)
        port = self.mgr.ensure_port_profile_created_on_apic(port_name)
        self.assert_responses_drained()
        self.assertEqual(port['name'], port_name)

    def test_ensure_port_profile_created_exc(self):
        port_name = mocked.APIC_PORT
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('infraAccPortP')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_port_profile_created_on_apic,
                          port_name)
        self.assert_responses_drained()

    def test_ensure_node_profile_created_for_switch_old(self):
        old_switch = mocked.APIC_NODE_PROF
        self.mock_response_for_get('infraNodeP', name=old_switch)
        self.mgr.ensure_node_profile_created_for_switch(old_switch)
        self.assert_responses_drained()
        old_name = self.mgr.node_profiles[old_switch]['object']['name']
        self.assertEqual(old_name, old_switch)

    def test_ensure_node_profile_created_for_switch_new(self):
        new_switch = mocked.APIC_NODE_PROF
        self.mock_response_for_get('infraNodeP')
        self.mock_responses_for_create('infraNodeP')
        self.mock_responses_for_create('infraLeafS')
        self.mock_responses_for_create('infraNodeBlk')
        self.mock_response_for_get('infraNodeP', name=new_switch)
        self.mgr.ensure_node_profile_created_for_switch(new_switch)
        self.assert_responses_drained()
        new_name = self.mgr.node_profiles[new_switch]['object']['name']
        self.assertEqual(new_name, new_switch)

    def test_ensure_node_profile_created_for_switch_new_exc(self):
        new_switch = mocked.APIC_NODE_PROF
        self.mock_response_for_get('infraNodeP')
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('infraNodeP')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_node_profile_created_for_switch,
                          new_switch)
        self.assert_responses_drained()

    def test_ensure_vmm_domain_created_old(self):
        dom = mocked.APIC_DOMAIN
        self.mock_response_for_get('vmmDomP', name=dom)
        self.mgr.ensure_vmm_domain_created_on_apic(dom)
        self.assert_responses_drained()
        old_dom = self.mgr.vmm_domain['name']
        self.assertEqual(old_dom, dom)

    def _mock_new_vmm_dom_responses(self, dom, seg_type=None):
        vmm = mocked.APIC_VMMP
        dn = self.mgr.apic.vmmDomP.mo.dn(vmm, dom)
        self.mock_response_for_get('vmmDomP')
        self.mock_responses_for_create('vmmDomP')
        if seg_type:
            self.mock_responses_for_create(seg_type)
        self.mock_response_for_get('vmmDomP', name=dom, dn=dn)

    def test_ensure_vmm_domain_created_new_no_vlan_ns(self):
        dom = mocked.APIC_DOMAIN
        self._mock_new_vmm_dom_responses(dom)
        self.mgr.ensure_vmm_domain_created_on_apic(dom)
        self.assert_responses_drained()
        new_dom = self.mgr.vmm_domain['name']
        self.assertEqual(new_dom, dom)

    def test_ensure_vmm_domain_created_new_no_vlan_ns_exc(self):
        dom = mocked.APIC_DOMAIN
        self.mock_response_for_get('vmmDomP')
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('vmmDomP')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_vmm_domain_created_on_apic, dom)
        self.assert_responses_drained()

    def test_ensure_vmm_domain_created_new_with_vlan_ns(self):
        dom = mocked.APIC_DOMAIN
        self._mock_new_vmm_dom_responses(dom, seg_type='infraRsVlanNs__vmm')
        ns = {'dn': 'test_vlan_ns'}
        self.mgr.ensure_vmm_domain_created_on_apic(dom, vlan_ns=ns)
        self.assert_responses_drained()
        new_dom = self.mgr.vmm_domain['name']
        self.assertEqual(new_dom, dom)

    def test_ensure_vmm_domain_created_new_with_vxlan_ns(self):
        dom = mocked.APIC_DOMAIN
        # TODO(Henry): mock seg_type vxlan when vxlan is ready
        self._mock_new_vmm_dom_responses(dom, seg_type=None)
        ns = {'dn': 'test_vxlan_ns'}
        self.mgr.ensure_vmm_domain_created_on_apic(dom, vxlan_ns=ns)
        self.assert_responses_drained()
        new_dom = self.mgr.vmm_domain['name']
        self.assertEqual(new_dom, dom)

    def test_ensure_infra_created_no_infra(self):
        self.mgr.switch_dict = {}
        self.mgr.ensure_infra_created_on_apic()

    def _ensure_infra_created_seq1_setup(self):
        am = 'neutron.plugins.ml2.drivers.cisco.apic.apic_manager.APICManager'
        np_create_for_switch = mock.patch(
            am + '.ensure_node_profile_created_for_switch').start()
        self.mock_db_query_filterby_first_return(None)
        pp_create_for_switch = mock.patch(
            am + '.ensure_port_profile_created_on_apic').start()
        pp_create_for_switch.return_value = {'dn': 'port_profile_dn'}
        return np_create_for_switch, pp_create_for_switch

    def test_ensure_infra_created_seq1(self):
        np_create_for_switch, pp_create_for_switch = (
            self._ensure_infra_created_seq1_setup())

        def _profile_for_module(aswitch, ppn, module):
            profile = mock.Mock()
            profile.ppn = ppn
            profile.hpselc_id = '-'.join([aswitch, module, 'hpselc_id'])
            return profile

        self.mgr.db.get_profile_for_module = mock.Mock(
            side_effect=_profile_for_module)
        self.mgr.db.get_profile_for_module_and_ports = mock.Mock(
            return_value=None)
        self.mgr.db.add_profile_for_module_and_ports = mock.Mock()

        num_switches = len(self.mgr.switch_dict)
        for loop in range(num_switches):
            self.mock_responses_for_create('infraRsAccPortP')
            self.mock_responses_for_create('infraPortBlk')

        self.mgr.ensure_infra_created_on_apic()
        self.assert_responses_drained()
        self.assertEqual(np_create_for_switch.call_count, num_switches)
        self.assertEqual(pp_create_for_switch.call_count, num_switches)
        for switch in self.mgr.switch_dict:
            np_create_for_switch.assert_any_call(switch)

    def test_ensure_infra_created_seq1_exc(self):
        np_create_for_switch, __ = self._ensure_infra_created_seq1_setup()
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('infraAccPortP')

        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_infra_created_on_apic)
        self.assert_responses_drained()
        self.assertTrue(np_create_for_switch.called)
        self.assertEqual(np_create_for_switch.call_count, 1)

    def _ensure_infra_created_seq2_setup(self):
        am = 'neutron.plugins.ml2.drivers.cisco.apic.apic_manager.APICManager'
        np_create_for_switch = mock.patch(
            am + '.ensure_node_profile_created_for_switch').start()

        def _profile_for_node(aswitch):
            profile = mock.Mock()
            profile.profile_id = '-'.join([aswitch, 'profile_id'])
            return profile

        self.mgr.db.get_port_profile_for_node = mock.Mock(
            side_effect=_profile_for_node)
        self.mgr.db.get_profile_for_module = mock.Mock(
            return_value=None)
        self.mgr.function_profile = {'dn': 'dn'}
        self.mgr.db.get_profile_for_module_and_ports = mock.Mock(
            return_value=True)

        return np_create_for_switch

    def test_ensure_infra_created_seq2(self):
        np_create_for_switch = self._ensure_infra_created_seq2_setup()

        num_switches = len(self.mgr.switch_dict)
        for loop in range(num_switches):
            self.mock_responses_for_create('infraHPortS')
            self.mock_responses_for_create('infraRsAccBaseGrp')

        self.mgr.ensure_infra_created_on_apic()
        self.assert_responses_drained()
        self.assertEqual(np_create_for_switch.call_count, num_switches)
        for switch in self.mgr.switch_dict:
            np_create_for_switch.assert_any_call(switch)

    def test_ensure_infra_created_seq2_exc(self):
        np_create_for_switch = self._ensure_infra_created_seq2_setup()

        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('infraHPortS')

        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_infra_created_on_apic)
        self.assert_responses_drained()
        self.assertTrue(np_create_for_switch.called)
        self.assertEqual(np_create_for_switch.call_count, 1)

    def test_ensure_context_unenforced_new_ctx(self):
        self.mock_response_for_get('fvCtx')
        self.mock_responses_for_create('fvCtx')
        self.mgr.ensure_context_unenforced()
        self.assert_responses_drained()

    def test_ensure_context_unenforced_pref1(self):
        self.mock_response_for_get('fvCtx', pcEnfPref='1')
        self.mock_response_for_post('fvCtx')
        self.mgr.ensure_context_unenforced()
        self.assert_responses_drained()

    def test_ensure_context_unenforced_pref2(self):
        self.mock_response_for_get('fvCtx', pcEnfPref='2')
        self.mgr.ensure_context_unenforced()
        self.assert_responses_drained()

    def _mock_vmm_dom_prereq(self, dom):
        self._mock_new_vmm_dom_responses(dom)
        self.mgr.ensure_vmm_domain_created_on_apic(dom)

    def _mock_new_phys_dom_responses(self, dom, seg_type=None):
        dn = self.mgr.apic.physDomP.mo.dn(dom)
        self.mock_response_for_get('physDomP')
        self.mock_responses_for_create('physDomP')
        if seg_type:
            self.mock_responses_for_create(seg_type)
        self.mock_response_for_get('physDomP', name=dom, dn=dn)

    def _mock_phys_dom_prereq(self, dom):
        self._mock_new_phys_dom_responses(dom)
        self.mgr.ensure_phys_domain_created_on_apic(dom)

    def test_ensure_entity_profile_created_old(self):
        ep = mocked.APIC_ATT_ENT_PROF
        self.mock_response_for_get('infraAttEntityP', name=ep)
        self.mgr.ensure_entity_profile_created_on_apic(ep)
        self.assert_responses_drained()

    def _mock_new_entity_profile(self, exc=None):
        self.mock_response_for_get('infraAttEntityP')
        self.mock_responses_for_create('infraAttEntityP')
        self.mock_responses_for_create('infraRsDomP')
        if exc:
            self.mock_error_get_response(exc, code='103', text=u'Fail')
        else:
            self.mock_response_for_get('infraAttEntityP')

    def test_ensure_entity_profile_created_new(self):
        self._mock_phys_dom_prereq(mocked.APIC_PDOM)
        ep = mocked.APIC_ATT_ENT_PROF
        self._mock_new_entity_profile()
        self.mgr.ensure_entity_profile_created_on_apic(ep)
        self.assert_responses_drained()

    def test_ensure_entity_profile_created_new_exc(self):
        self._mock_phys_dom_prereq(mocked.APIC_PDOM)
        ep = mocked.APIC_ATT_ENT_PROF
        self._mock_new_entity_profile(exc=wexc.HTTPBadRequest)
        self.mock_response_for_post('infraAttEntityP')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_entity_profile_created_on_apic, ep)
        self.assert_responses_drained()

    def _mock_entity_profile_preqreq(self):
        self._mock_phys_dom_prereq(mocked.APIC_PDOM)
        ep = mocked.APIC_ATT_ENT_PROF
        self._mock_new_entity_profile()
        self.mgr.ensure_entity_profile_created_on_apic(ep)

    def test_ensure_function_profile_created_old(self):
        self._mock_entity_profile_preqreq()
        fp = mocked.APIC_FUNC_PROF
        self.mock_response_for_get('infraAccPortGrp', name=fp)
        self.mgr.ensure_function_profile_created_on_apic(fp)
        self.assert_responses_drained()
        old_fp = self.mgr.function_profile['name']
        self.assertEqual(old_fp, fp)

    def _mock_new_function_profile(self, fp):
        dn = self.mgr.apic.infraAttEntityP.mo.dn(fp)
        self.mock_responses_for_create('infraAccPortGrp')
        self.mock_responses_for_create('infraRsAttEntP')
        self.mock_response_for_get('infraAccPortGrp', name=fp, dn=dn)

    def test_ensure_function_profile_created_new(self):
        fp = mocked.APIC_FUNC_PROF
        dn = self.mgr.apic.infraAttEntityP.mo.dn(fp)
        self.mgr.entity_profile = {'dn': dn}
        self.mock_response_for_get('infraAccPortGrp')
        self.mock_responses_for_create('infraAccPortGrp')
        self.mock_responses_for_create('infraRsAttEntP')
        self.mock_response_for_get('infraAccPortGrp', name=fp, dn=dn)
        self.mgr.ensure_function_profile_created_on_apic(fp)
        self.assert_responses_drained()
        new_fp = self.mgr.function_profile['name']
        self.assertEqual(new_fp, fp)

    def test_ensure_function_profile_created_new_exc(self):
        fp = mocked.APIC_FUNC_PROF
        dn = self.mgr.apic.infraAttEntityP.mo.dn(fp)
        self.mgr.entity_profile = {'dn': dn}
        self.mock_response_for_get('infraAccPortGrp')
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('infraAccPortGrp')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_function_profile_created_on_apic, fp)
        self.assert_responses_drained()

    def test_ensure_vlan_ns_created_old(self):
        ns = mocked.APIC_VLAN_NAME
        mode = mocked.APIC_VLAN_MODE
        self.mock_response_for_get('fvnsVlanInstP', name=ns, mode=mode)
        new_ns = self.mgr.ensure_vlan_ns_created_on_apic(ns, '100', '199')
        self.assert_responses_drained()
        self.assertIsNone(new_ns)

    def _mock_new_vlan_instance(self, ns, vlan_encap=None):
        self.mock_responses_for_create('fvnsVlanInstP')
        if vlan_encap:
            self.mock_response_for_get('fvnsEncapBlk', **vlan_encap)
        else:
            self.mock_response_for_get('fvnsEncapBlk')
            self.mock_responses_for_create('fvnsEncapBlk__vlan')
        self.mock_response_for_get('fvnsVlanInstP', name=ns)

    def test_ensure_vlan_ns_created_new_no_encap(self):
        ns = mocked.APIC_VLAN_NAME
        self.mock_response_for_get('fvnsVlanInstP')
        self._mock_new_vlan_instance(ns)
        new_ns = self.mgr.ensure_vlan_ns_created_on_apic(ns, '200', '299')
        self.assert_responses_drained()
        self.assertEqual(new_ns['name'], ns)

    def test_ensure_vlan_ns_created_new_exc(self):
        ns = mocked.APIC_VLAN_NAME
        self.mock_response_for_get('fvnsVlanInstP')
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('fvnsVlanInstP')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_vlan_ns_created_on_apic,
                          ns, '200', '299')
        self.assert_responses_drained()

    def test_ensure_vlan_ns_created_new_with_encap(self):
        ns = mocked.APIC_VLAN_NAME
        self.mock_response_for_get('fvnsVlanInstP')
        ns_args = {'name': 'encap', 'from': '300', 'to': '399'}
        self._mock_new_vlan_instance(ns, vlan_encap=ns_args)
        new_ns = self.mgr.ensure_vlan_ns_created_on_apic(ns, '300', '399')
        self.assert_responses_drained()
        self.assertEqual(new_ns['name'], ns)

    def test_ensure_tenant_created_on_apic(self):
        self.mock_response_for_get('fvTenant', name='any')
        self.mgr.ensure_tenant_created_on_apic('two')
        self.mock_response_for_get('fvTenant')
        self.mock_responses_for_create('fvTenant')
        self.mgr.ensure_tenant_created_on_apic('four')
        self.assert_responses_drained()

    def test_ensure_bd_created_existing_bd(self):
        self.mock_response_for_get('fvBD', name='BD')
        self.mgr.ensure_bd_created_on_apic('t1', 'two')
        self.assert_responses_drained()

    def test_ensure_bd_created_not_ctx(self):
        self.mock_response_for_get('fvBD')
        self.mock_responses_for_create('fvBD')
        self.mock_response_for_get('fvCtx')
        self.mock_responses_for_create('fvCtx')
        self.mock_responses_for_create('fvRsCtx')
        self.mgr.ensure_bd_created_on_apic('t2', 'three')
        self.assert_responses_drained()

    def test_ensure_bd_created_exc(self):
        self.mock_response_for_get('fvBD')
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('fvBD')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_bd_created_on_apic, 't2', 'three')
        self.assert_responses_drained()

    def test_ensure_bd_created_ctx_pref1(self):
        self.mock_response_for_get('fvBD')
        self.mock_responses_for_create('fvBD')
        self.mock_response_for_get('fvCtx', pcEnfPref='1')
        self.mock_responses_for_create('fvRsCtx')
        self.mgr.ensure_bd_created_on_apic('t3', 'four')
        self.assert_responses_drained()

    def test_ensure_bd_created_ctx_pref2(self):
        self.mock_response_for_get('fvBD')
        self.mock_responses_for_create('fvBD')
        self.mock_response_for_get('fvCtx', pcEnfPref='2')
        self.mock_response_for_post('fvCtx')
        self.mock_responses_for_create('fvRsCtx')
        self.mgr.ensure_bd_created_on_apic('t3', 'four')
        self.assert_responses_drained()

    def test_delete_bd(self):
        self.mock_response_for_post('fvBD')
        self.mgr.delete_bd_on_apic('t1', 'bd')
        self.assert_responses_drained()

    def test_ensure_subnet_created(self):
        self.mock_response_for_get('fvSubnet', name='sn1')
        self.mgr.ensure_subnet_created_on_apic('t0', 'bd1', '2.2.2.2/8')
        self.mock_response_for_get('fvSubnet')
        self.mock_responses_for_create('fvSubnet')
        self.mgr.ensure_subnet_created_on_apic('t2', 'bd3', '4.4.4.4/16')
        self.assert_responses_drained()

    def test_ensure_filter_created(self):
        self.mock_response_for_get('vzFilter', name='f1')
        self.mgr.ensure_filter_created_on_apic('t1', 'two')
        self.mock_response_for_get('vzFilter')
        self.mock_responses_for_create('vzFilter')
        self.mgr.ensure_filter_created_on_apic('t2', 'four')
        self.assert_responses_drained()

    def test_ensure_epg_created_for_network_old(self):
        self.mock_db_query_filterby_first_return('faked')
        epg = self.mgr.ensure_epg_created_for_network('X', 'Y', 'Z')
        self.assertEqual(epg, 'faked')

    def test_ensure_epg_created_for_network_new(self):
        tenant = mocked.APIC_TENANT
        network = mocked.APIC_NETWORK
        netname = mocked.APIC_NETNAME
        self._mock_phys_dom_prereq(mocked.APIC_PDOM)
        self.mock_db_query_filterby_first_return(None)
        self.mock_responses_for_create('fvAEPg')
        self.mock_response_for_get('fvBD', name=network)
        self.mock_responses_for_create('fvRsBd')
        self.mock_responses_for_create('fvRsDomAtt')
        new_epg = self.mgr.ensure_epg_created_for_network(tenant,
                                                          network, netname)
        self.assert_responses_drained()
        self.assertEqual(new_epg.network_id, network)
        self.assertTrue(self.mocked_session.add.called)
        self.assertTrue(self.mocked_session.flush.called)

    def test_ensure_epg_created_for_network_exc(self):
        tenant = mocked.APIC_TENANT
        network = mocked.APIC_NETWORK
        netname = mocked.APIC_NETNAME
        self.mock_db_query_filterby_first_return(None)
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('fvAEPg')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.ensure_epg_created_for_network,
                          tenant, network, netname)
        self.assert_responses_drained()

    def test_delete_epg_for_network_no_epg(self):
        self.mock_db_query_filterby_first_return(None)
        self.mgr.delete_epg_for_network('tenant', 'network')

    def test_delete_epg_for_network(self):
        epg = mock.Mock()
        epg.epg_id = mocked.APIC_EPG
        self.mock_db_query_filterby_first_return(epg)
        self.mock_response_for_post('fvAEPg')
        self.mgr.delete_epg_for_network('tenant', 'network')
        self.assertTrue(self.mocked_session.delete.called)
        self.assertTrue(self.mocked_session.flush.called)

    def test_ensure_path_created_for_port(self):
        epg = mock.Mock()
        epg.epg_id = 'epg01'
        eepg = mock.Mock(return_value=epg)
        apic_manager.APICManager.ensure_epg_created_for_network = eepg
        self.mock_response_for_get('fvRsPathAtt', tDn='foo')
        self.mgr.ensure_path_created_for_port('tenant', 'network', 'rhel01',
                                              'static', 'netname')
        self.assert_responses_drained()

    def test_ensure_path_created_for_port_no_path_att(self):
        epg = mock.Mock()
        epg.epg_id = 'epg2'
        eepg = mock.Mock(return_value=epg)
        self.mgr.ensure_epg_created_for_network = eepg
        self.mock_response_for_get('fvRsPathAtt')
        self.mock_responses_for_create('fvRsPathAtt')
        self.mgr.ensure_path_created_for_port('tenant', 'network', 'ubuntu2',
                                              'static', 'netname')
        self.assert_responses_drained()

    def test_ensure_path_created_for_port_unknown_host(self):
        epg = mock.Mock()
        epg.epg_id = 'epg3'
        eepg = mock.Mock(return_value=epg)
        apic_manager.APICManager.ensure_epg_created_for_network = eepg
        self.mock_response_for_get('fvRsPathAtt', tDn='foo')
        self.assertRaises(cexc.ApicHostNotConfigured,
                          self.mgr.ensure_path_created_for_port,
                          'tenant', 'network', 'cirros3', 'static', 'netname')

    def test_create_tenant_filter(self):
        tenant = mocked.APIC_TENANT
        self.mock_responses_for_create('vzFilter')
        self.mock_responses_for_create('vzEntry')
        filter_id = self.mgr.create_tenant_filter(tenant)
        self.assert_responses_drained()
        self.assertTrue(uuidutils.is_uuid_like(str(filter_id)))

    def test_create_tenant_filter_exc(self):
        tenant = mocked.APIC_TENANT
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('vzFilter')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.create_tenant_filter, tenant)
        self.assert_responses_drained()

    def test_set_contract_for_epg_consumer(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_responses_for_create('fvRsCons')
        self.mgr.set_contract_for_epg(tenant, epg, contract)
        self.assert_responses_drained()

    def test_set_contract_for_epg_provider(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        epg_obj = mock.Mock()
        epg_obj.epg_id = epg
        epg_obj.provider = False
        self.mock_db_query_filterby_first_return(epg_obj)
        self.mock_responses_for_create('fvRsProv')
        self.mock_response_for_post('vzBrCP')
        self.mgr.set_contract_for_epg(tenant, epg, contract, provider=True)
        self.assert_responses_drained()
        self.assertTrue(self.mocked_session.merge.called)
        self.assertTrue(self.mocked_session.flush.called)
        self.assertTrue(epg_obj.provider)

    def test_set_contract_for_epg_provider_exc(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('vzBrCP')
        self.mock_response_for_post('fvRsProv')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.set_contract_for_epg,
                          tenant, epg, contract, provider=True)
        self.assert_responses_drained()

    def test_delete_contract_for_epg_consumer(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        self.mock_response_for_post('fvRsCons')
        self.mgr.delete_contract_for_epg(tenant, epg, contract)
        self.assert_responses_drained()

    def test_delete_contract_for_epg_provider(self):
        tenant = mocked.APIC_TENANT
        epg = mocked.APIC_EPG
        contract = mocked.APIC_CONTRACT
        epg_obj = mock.Mock()
        epg_obj.epg_id = epg + '-other'
        epg_obj.provider = False
        self.mock_db_query_filterby_first_return(epg_obj)
        self.mock_response_for_post('fvRsProv')
        self.mock_response_for_post('fvRsCons')
        self.mock_responses_for_create('fvRsProv')
        self.mock_response_for_post('vzBrCP')
        self.mgr.delete_contract_for_epg(tenant, epg, contract, provider=True)
        self.assert_responses_drained()
        self.assertTrue(self.mocked_session.merge.called)
        self.assertTrue(self.mocked_session.flush.called)
        self.assertTrue(epg_obj.provider)

    def test_create_tenant_contract_existing(self):
        tenant = mocked.APIC_TENANT
        contract = mocked.APIC_CONTRACT
        self.mock_db_query_filterby_first_return(contract)
        new_contract = self.mgr.create_tenant_contract(tenant)
        self.assertEqual(new_contract, contract)

    def test_create_tenant_contract_new(self):
        tenant = mocked.APIC_TENANT
        contract = mocked.APIC_CONTRACT
        dn = self.mgr.apic.vzBrCP.mo.dn(tenant, contract)
        self.mock_db_query_filterby_first_return(None)
        self.mock_responses_for_create('vzBrCP')
        self.mock_response_for_get('vzBrCP', dn=dn)
        self.mock_responses_for_create('vzSubj')
        self.mock_responses_for_create('vzFilter')
        self.mock_responses_for_create('vzEntry')
        self.mock_responses_for_create('vzInTerm')
        self.mock_responses_for_create('vzRsFiltAtt__In')
        self.mock_responses_for_create('vzOutTerm')
        self.mock_responses_for_create('vzRsFiltAtt__Out')
        self.mock_responses_for_create('vzCPIf')
        self.mock_responses_for_create('vzRsIf')
        new_contract = self.mgr.create_tenant_contract(tenant)
        self.assert_responses_drained()
        self.assertTrue(self.mocked_session.add.called)
        self.assertTrue(self.mocked_session.flush.called)
        self.assertEqual(new_contract['tenant_id'], tenant)

    def test_create_tenant_contract_exc(self):
        tenant = mocked.APIC_TENANT
        self.mock_db_query_filterby_first_return(None)
        self.mock_error_post_response(wexc.HTTPBadRequest)
        self.mock_response_for_post('vzBrCP')
        self.assertRaises(cexc.ApicResponseNotOk,
                          self.mgr.create_tenant_contract, tenant)
        self.assert_responses_drained()
