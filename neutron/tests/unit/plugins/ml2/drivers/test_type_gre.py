# Copyright (c) 2013 OpenStack Foundation
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

from oslo_db import exception as db_exc
from sqlalchemy.orm import exc as sa_exc
import testtools

from neutron.db import api as db_api
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import config
from neutron.plugins.ml2.drivers import type_gre
from neutron.tests.unit.plugins.ml2.drivers import base_type_tunnel
from neutron.tests.unit.plugins.ml2 import test_rpc
from neutron.tests.unit import testlib_api


TUNNEL_IP_ONE = "10.10.10.10"
TUNNEL_IP_TWO = "10.10.10.20"
HOST_ONE = 'fake_host_one'
HOST_TWO = 'fake_host_two'


def _add_allocation(session, gre_id, allocated=False):
    allocation = type_gre.GreAllocation(gre_id=gre_id, allocated=allocated)
    allocation.save(session)


def _get_allocation(session, gre_id):
    return session.query(type_gre.GreAllocation).filter_by(
        gre_id=gre_id).one()


class GreTypeTest(base_type_tunnel.TunnelTypeTestMixin,
                  testlib_api.SqlTestCase):
    DRIVER_MODULE = type_gre
    DRIVER_CLASS = type_gre.GreTypeDriver
    TYPE = p_const.TYPE_GRE

    def test_get_endpoints(self):
        self.add_endpoint()
        self.add_endpoint(
            base_type_tunnel.TUNNEL_IP_TWO, base_type_tunnel.HOST_TWO)

        endpoints = self.driver.get_endpoints()
        for endpoint in endpoints:
            if endpoint['ip_address'] == base_type_tunnel.TUNNEL_IP_ONE:
                self.assertEqual(base_type_tunnel.HOST_ONE, endpoint['host'])
            elif endpoint['ip_address'] == base_type_tunnel.TUNNEL_IP_TWO:
                self.assertEqual(base_type_tunnel.HOST_TWO, endpoint['host'])

    def test_sync_allocations_entry_added_during_session(self):
        with mock.patch.object(self.driver, '_add_allocation',
                               side_effect=db_exc.DBDuplicateEntry) as (
                mock_add_allocation):
            self.driver.sync_allocations()
            self.assertTrue(mock_add_allocation.called)

    def test__add_allocation_not_existing(self):
        session = db_api.get_session()
        _add_allocation(session, gre_id=1)
        self.driver._add_allocation(session, {1, 2})
        _get_allocation(session, 2)

    def test__add_allocation_existing_allocated_is_kept(self):
        session = db_api.get_session()
        _add_allocation(session, gre_id=1, allocated=True)
        self.driver._add_allocation(session, {2})
        _get_allocation(session, 1)

    def test__add_allocation_existing_not_allocated_is_removed(self):
        session = db_api.get_session()
        _add_allocation(session, gre_id=1)
        self.driver._add_allocation(session, {2})
        with testtools.ExpectedException(sa_exc.NoResultFound):
            _get_allocation(session, 1)

    def test_get_mtu(self):
        config.cfg.CONF.set_override('segment_mtu', 1500, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 1475, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1475 - p_const.GRE_ENCAP_OVERHEAD,
                         self.driver.get_mtu('physnet1'))

        config.cfg.CONF.set_override('segment_mtu', 1425, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 1475, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1400, 'physnet2': 1400}
        self.assertEqual(1425 - p_const.GRE_ENCAP_OVERHEAD,
                         self.driver.get_mtu('physnet1'))

        config.cfg.CONF.set_override('segment_mtu', 0, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 1475, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1425}
        self.assertEqual(1475 - p_const.GRE_ENCAP_OVERHEAD,
                         self.driver.get_mtu('physnet2'))

        config.cfg.CONF.set_override('segment_mtu', 0, group='ml2')
        config.cfg.CONF.set_override('path_mtu', 0, group='ml2')
        self.driver.physnet_mtus = {}
        self.assertEqual(0, self.driver.get_mtu('physnet1'))


class GreTypeMultiRangeTest(base_type_tunnel.TunnelTypeMultiRangeTestMixin,
                            testlib_api.SqlTestCase):
    DRIVER_CLASS = type_gre.GreTypeDriver


class GreTypeRpcCallbackTest(base_type_tunnel.TunnelRpcCallbackTestMixin,
                             test_rpc.RpcCallbacksTestCase,
                             testlib_api.SqlTestCase):
    DRIVER_CLASS = type_gre.GreTypeDriver
    TYPE = p_const.TYPE_GRE
