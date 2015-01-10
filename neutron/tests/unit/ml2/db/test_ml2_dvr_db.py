# Copyright (c) 2014 OpenStack Foundation, all rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from sqlalchemy.orm import query

from neutron import context
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions import portbindings
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit import testlib_api


class Ml2DvrDBTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(Ml2DvrDBTestCase, self).setUp()
        self.ctx = context.get_admin_context()

    def _setup_neutron_network(self, network_id, port_ids):
        with self.ctx.session.begin(subtransactions=True):
            self.ctx.session.add(models_v2.Network(id=network_id))
            ports = []
            for port_id in port_ids:
                mac_address = (db_base_plugin_v2.NeutronDbPluginV2.
                               _generate_mac())
                port = models_v2.Port(id=port_id,
                                      network_id=network_id,
                                      mac_address=mac_address,
                                      admin_state_up=True,
                                      status='ACTIVE',
                                      device_id='',
                                      device_owner='')
                self.ctx.session.add(port)
                ports.append(port)
            return ports

    def _setup_neutron_router(self):
        with self.ctx.session.begin(subtransactions=True):
            router = l3_db.Router()
            self.ctx.session.add(router)
            return router

    def _setup_dvr_binding(self, network_id, port_id, router_id, host_id):
        with self.ctx.session.begin(subtransactions=True):
            record = ml2_models.DVRPortBinding(
                port_id=port_id,
                host=host_id,
                router_id=router_id,
                vif_type=portbindings.VIF_TYPE_UNBOUND,
                vnic_type=portbindings.VNIC_NORMAL,
                cap_port_filter=False,
                status='DOWN')
            self.ctx.session.add(record)
            return record

    def test_ensure_dvr_port_binding_deals_with_db_duplicate(self):
        network_id = 'foo_network_id'
        port_id = 'foo_port_id'
        router_id = 'foo_router_id'
        host_id = 'foo_host_id'
        self._setup_neutron_network(network_id, [port_id])
        self._setup_dvr_binding(network_id, port_id, router_id, host_id)
        with mock.patch.object(query.Query, 'first') as query_first:
            query_first.return_value = []
            with mock.patch.object(ml2_db.LOG, 'debug') as log_trace:
                binding = ml2_db.ensure_dvr_port_binding(
                    self.ctx.session, port_id, host_id, router_id)
        self.assertTrue(query_first.called)
        self.assertTrue(log_trace.called)
        self.assertEqual(port_id, binding.port_id)

    def test_ensure_dvr_port_binding(self):
        network_id = 'foo_network_id'
        port_id = 'foo_port_id'
        self._setup_neutron_network(network_id, [port_id])
        router = self._setup_neutron_router()
        ml2_db.ensure_dvr_port_binding(
            self.ctx.session, port_id, 'foo_host', router.id)
        expected = (self.ctx.session.query(ml2_models.DVRPortBinding).
                    filter_by(port_id=port_id).one())
        self.assertEqual(expected.port_id, port_id)

    def test_ensure_dvr_port_binding_multiple_bindings(self):
        network_id = 'foo_network_id'
        port_id = 'foo_port_id'
        self._setup_neutron_network(network_id, [port_id])
        router = self._setup_neutron_router()
        ml2_db.ensure_dvr_port_binding(
            self.ctx.session, port_id, 'foo_host_1', router.id)
        ml2_db.ensure_dvr_port_binding(
            self.ctx.session, port_id, 'foo_host_2', router.id)
        bindings = (self.ctx.session.query(ml2_models.DVRPortBinding).
                    filter_by(port_id=port_id).all())
        self.assertEqual(2, len(bindings))

    def test_delete_dvr_port_binding(self):
        network_id = 'foo_network_id'
        port_id = 'foo_port_id'
        self._setup_neutron_network(network_id, [port_id])
        router = self._setup_neutron_router()
        binding = self._setup_dvr_binding(
            network_id, port_id, router.id, 'foo_host_id')
        ml2_db.delete_dvr_port_binding(
            self.ctx.session, port_id, 'foo_host_id')
        count = (self.ctx.session.query(ml2_models.DVRPortBinding).
            filter_by(port_id=binding.port_id).count())
        self.assertFalse(count)

    def test_delete_dvr_port_binding_not_found(self):
        ml2_db.delete_dvr_port_binding(
            self.ctx.session, 'foo_port_id', 'foo_host')

    def test_delete_dvr_port_binding_if_stale(self):
        network_id = 'foo_network_id'
        port_id = 'foo_port_id'
        self._setup_neutron_network(network_id, [port_id])
        binding = self._setup_dvr_binding(
            network_id, port_id, None, 'foo_host_id')

        ml2_db.delete_dvr_port_binding_if_stale(self.ctx.session, binding)
        count = (self.ctx.session.query(ml2_models.DVRPortBinding).
            filter_by(port_id=binding.port_id).count())
        self.assertFalse(count)

    def test_get_dvr_port_binding_by_host_not_found(self):
        port = ml2_db.get_dvr_port_binding_by_host(
            self.ctx.session, 'foo_port_id', 'foo_host_id')
        self.assertIsNone(port)

    def test_get_dvr_port_bindings_not_found(self):
        port = ml2_db.get_dvr_port_bindings(self.ctx.session, 'foo_port_id')
        self.assertFalse(len(port))

    def test_get_dvr_port_bindings(self):
        network_id = 'foo_network_id'
        port_id_1 = 'foo_port_id_1'
        port_id_2 = 'foo_port_id_2'
        self._setup_neutron_network(network_id, [port_id_1, port_id_2])
        router = self._setup_neutron_router()
        self._setup_dvr_binding(
            network_id, port_id_1, router.id, 'foo_host_id_1')
        self._setup_dvr_binding(
            network_id, port_id_1, router.id, 'foo_host_id_2')
        ports = ml2_db.get_dvr_port_bindings(self.ctx.session, 'foo_port_id')
        self.assertEqual(2, len(ports))
