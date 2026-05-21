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

from neutron_lib import constants as n_const
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.agent.ovn.extensions.evpn import constants as evpn_agent_const
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.services.bgp import constants as bgp_const
from neutron.services.evpn import commands as evpn_ovn
from neutron.services.evpn import constants as evpn_const
from neutron.tests.functional import base as func_base
from neutron.tests.functional.services import bgp


class CreateEVPNRouterCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.router_id = uuidutils.generate_uuid()
        self.lr_name = ovn_utils.ovn_name(self.router_id)
        self.vni = 5000
        self.vlan = 100
        self.nb_api.lr_add(self.lr_name).execute(check_error=True)

    def _execute(self, router_id=None, vni=None, vlan=None):
        evpn_ovn.CreateEVPNRouterCommand(
            self.nb_api, router_id or self.router_id,
            vni or self.vni, vlan or self.vlan,
        ).execute(check_error=True)

    def test_sets_dynamic_routing_options_on_router(self):
        self._execute()

        lr = self.nb_api.lr_get(self.lr_name).execute(check_error=True)
        self.assertEqual('true', lr.options.get(
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING))
        self.assertEqual(str(self.vni), lr.options.get(
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_VRF_ID))
        self.assertEqual(
            ('vr%s' % self.router_id)[:n_const.DEVICE_NAME_MAX_LEN],
            lr.options.get(
                ovn_const.LR_OPTIONS_DR_VRF_NAME))

    def test_preserves_existing_router_options(self):
        self.nb_api.db_set(
            'Logical_Router', self.lr_name,
            options={'existing-key': 'existing-value'},
        ).execute(check_error=True)

        self._execute()

        lr = self.nb_api.lr_get(self.lr_name).execute(check_error=True)
        self.assertEqual('existing-value',
                         lr.options.get('existing-key'))
        self.assertEqual('true', lr.options.get(
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING))

    def test_creates_dummy_logical_switch(self):
        self._execute()

        ls_name = evpn_ovn._evpn_ls_name(self.vni)
        ls = self.nb_api.ls_get(ls_name).execute(check_error=True)
        self.assertEqual(ls_name, ls.name)
        self.assertEqual(str(self.vni), ls.other_config.get(
            ovn_const.LS_OTHER_CFG_DR_VNI))
        self.assertEqual(
            'vl-%d-%s' % (
                evpn_ovn.CreateEVPNRouterCommand.SVD_INDEX, self.vlan),
            ls.other_config.get(ovn_const.LS_OTHER_CFG_DR_BRIDGE_IFNAME))
        self.assertEqual(
            "%s%d" % (evpn_agent_const.EVPN_VXLAN_IFNAME,
                      evpn_ovn.CreateEVPNRouterCommand.SVD_INDEX),
            ls.other_config.get(
                ovn_const.LS_OTHER_CFG_DR_VXLAN_IFNAME))

    def test_creates_logical_router_port(self):
        self._execute()

        lrp_name = evpn_ovn._evpn_lrp_name(self.router_id, self.vni)
        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual(lrp_name, lrp.name)
        self.assertEqual('true', lrp.options.get(
            bgp_const.LRP_OPTIONS_DYNAMIC_ROUTING_MAINTAIN_VRF))
        self.assertEqual(str(self.vni), lrp.external_ids.get(
            evpn_const.EVPN_LRP_VNI_EXT_ID_KEY))

    def test_creates_logical_switch_port(self):
        self._execute()

        ls_name = evpn_ovn._evpn_ls_name(self.vni)
        lsp_name = evpn_ovn._evpn_lsp_name(self.router_id, self.vni)
        lrp_name = evpn_ovn._evpn_lrp_name(self.router_id, self.vni)

        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.assertEqual('router', lsp.type)
        self.assertEqual(lrp_name, lsp.options.get('router-port'))
        self.assertEqual([ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER],
                         lsp.addresses)

        ls = self.nb_api.ls_get(ls_name).execute(check_error=True)
        lsp_uuids = {p.uuid for p in ls.ports}
        self.assertIn(lsp.uuid, lsp_uuids)

    def test_idempotent(self):
        self._execute()
        self._execute()

        ls_name = evpn_ovn._evpn_ls_name(self.vni)
        lrp_name = evpn_ovn._evpn_lrp_name(self.router_id, self.vni)
        lsp_name = evpn_ovn._evpn_lsp_name(self.router_id, self.vni)

        self.nb_api.ls_get(ls_name).execute(check_error=True)
        self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.nb_api.lsp_get(lsp_name).execute(check_error=True)

        lr = self.nb_api.lr_get(self.lr_name).execute(check_error=True)
        self.assertEqual('true', lr.options.get(
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING))

    def test_updates_existing_lrp_options_and_external_ids(self):
        self._execute()

        lrp_name = evpn_ovn._evpn_lrp_name(self.router_id, self.vni)
        self.nb_api.db_set(
            'Logical_Router_Port', lrp_name,
            options={'dynamic-routing-maintain-vrf': 'false'},
            external_ids={'vni': '9999'},
        ).execute(check_error=True)

        self._execute()

        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual('true', lrp.options.get(
            bgp_const.LRP_OPTIONS_DYNAMIC_ROUTING_MAINTAIN_VRF))
        self.assertEqual(str(self.vni), lrp.external_ids.get('vni'))

    def test_updates_existing_lsp_attributes(self):
        self._execute()

        lsp_name = evpn_ovn._evpn_lsp_name(self.router_id, self.vni)
        self.nb_api.db_set(
            'Logical_Switch_Port', lsp_name,
            type='patch',
            options={'router-port': 'wrong-port'},
        ).execute(check_error=True)

        self._execute()

        lrp_name = evpn_ovn._evpn_lrp_name(self.router_id, self.vni)
        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.assertEqual('router', lsp.type)
        self.assertEqual(lrp_name, lsp.options.get('router-port'))
        self.assertEqual([ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER],
                         lsp.addresses)


class DeleteEVPNRouterCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.router_id = uuidutils.generate_uuid()
        self.lr_name = ovn_utils.ovn_name(self.router_id)
        self.vni = 6000
        self.vlan = 200
        self.nb_api.lr_add(self.lr_name).execute(check_error=True)

        evpn_ovn.CreateEVPNRouterCommand(
            self.nb_api, self.router_id, self.vni, self.vlan,
        ).execute(check_error=True)

    def _execute(self, vni=None):
        evpn_ovn.DeleteEVPNRouterCommand(
            self.nb_api, vni or self.vni,
        ).execute(check_error=True)

    def test_deletes_dummy_logical_switch(self):
        ls_name = evpn_ovn._evpn_ls_name(self.vni)
        self.nb_api.ls_get(ls_name).execute(check_error=True)

        self._execute()

        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.ls_get(ls_name).execute, check_error=True)

    def test_deletes_logical_switch_port_via_cascade(self):
        lsp_name = evpn_ovn._evpn_lsp_name(self.router_id, self.vni)
        self.nb_api.lsp_get(lsp_name).execute(check_error=True)

        self._execute()

        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lsp_get(lsp_name).execute, check_error=True)

    def test_does_not_delete_router_or_lrp(self):
        lrp_name = evpn_ovn._evpn_lrp_name(self.router_id, self.vni)

        self._execute()

        self.nb_api.lr_get(self.lr_name).execute(check_error=True)
        self.nb_api.lrp_get(lrp_name).execute(check_error=True)

    def test_idempotent(self):
        self._execute()
        self._execute()

    def test_nonexistent_vni(self):
        self._execute(vni=9999)


class AdvertiseHostCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.lr_name = func_base.get_unique_name("lr")
        self.nb_api.lr_add(self.lr_name).execute(check_error=True)

    def _create_lrp(self, port_id, **kwargs):
        lrp_name = ovn_utils.ovn_lrouter_port_name(port_id)
        self.nb_api.lrp_add(
            self.lr_name, lrp_name,
            mac='00:00:00:00:00:01',
            networks=['192.168.1.1/24'],
            **kwargs,
        ).execute(check_error=True)
        return lrp_name

    def test_sets_redistribute_option(self):
        port_id = uuidutils.generate_uuid()
        lrp_name = self._create_lrp(port_id)

        evpn_ovn.AdvertiseHostCommand(
            self.nb_api, port_id).execute(check_error=True)

        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual(
            'connected-as-host',
            lrp.options.get(
                bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE))

    def test_preserves_existing_options(self):
        port_id = uuidutils.generate_uuid()
        lrp_name = self._create_lrp(
            port_id, options={'existing-key': 'existing-value'})

        evpn_ovn.AdvertiseHostCommand(
            self.nb_api, port_id).execute(check_error=True)

        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual('existing-value',
                         lrp.options.get('existing-key'))
        self.assertEqual(
            'connected-as-host',
            lrp.options.get(
                bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE))

    def test_idempotent(self):
        port_id = uuidutils.generate_uuid()
        lrp_name = self._create_lrp(port_id)

        evpn_ovn.AdvertiseHostCommand(
            self.nb_api, port_id).execute(check_error=True)
        evpn_ovn.AdvertiseHostCommand(
            self.nb_api, port_id).execute(check_error=True)

        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual(
            'connected-as-host',
            lrp.options.get(
                bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE))
