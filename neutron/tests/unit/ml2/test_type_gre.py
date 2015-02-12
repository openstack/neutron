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

from oslo.db import exception as db_exc
from sqlalchemy.orm import exc as sa_exc
import testtools

from neutron.db import api as db_api
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.drivers import type_gre
from neutron.tests.unit.ml2 import test_type_vxlan
from neutron.tests.unit import testlib_api


TUNNEL_IP_ONE = "10.10.10.10"
TUNNEL_IP_TWO = "10.10.10.20"


def _add_allocation(session, gre_id, allocated=False):
    allocation = type_gre.GreAllocation(gre_id=gre_id, allocated=allocated)
    allocation.save(session)


def _get_allocation(session, gre_id):
    return session.query(type_gre.GreAllocation).filter_by(
        gre_id=gre_id).one()


class GreTypeTest(test_type_vxlan.TunnelTypeTestMixin,
                  testlib_api.SqlTestCase):
    DRIVER_CLASS = type_gre.GreTypeDriver
    TYPE = p_const.TYPE_GRE

    def test_endpoints(self):
        tun_1 = self.driver.add_endpoint(TUNNEL_IP_ONE)
        tun_2 = self.driver.add_endpoint(TUNNEL_IP_TWO)
        self.assertEqual(TUNNEL_IP_ONE, tun_1.ip_address)
        self.assertEqual(TUNNEL_IP_TWO, tun_2.ip_address)

        # Get all the endpoints
        endpoints = self.driver.get_endpoints()
        for endpoint in endpoints:
            self.assertIn(endpoint['ip_address'],
                          [TUNNEL_IP_ONE, TUNNEL_IP_TWO])

    def test_add_same_ip_endpoints(self):
        self.driver.add_endpoint(TUNNEL_IP_ONE)
        with mock.patch.object(type_gre.LOG, 'warning') as log_warn:
            self.driver.add_endpoint(TUNNEL_IP_ONE)
        log_warn.assert_called_once_with(mock.ANY, TUNNEL_IP_ONE)

    def test_sync_allocations_entry_added_during_session(self):
        with mock.patch.object(self.driver, '_add_allocation',
                               side_effect=db_exc.DBDuplicateEntry) as (
                mock_add_allocation):
            self.driver.sync_allocations()
            self.assertTrue(mock_add_allocation.called)

    def test__add_allocation_not_existing(self):
        session = db_api.get_session()
        _add_allocation(session, gre_id=1)
        self.driver._add_allocation(session, set([1, 2]))
        _get_allocation(session, 2)

    def test__add_allocation_existing_allocated_is_kept(self):
        session = db_api.get_session()
        _add_allocation(session, gre_id=1, allocated=True)
        self.driver._add_allocation(session, set([2]))
        _get_allocation(session, 1)

    def test__add_allocation_existing_not_allocated_is_removed(self):
        session = db_api.get_session()
        _add_allocation(session, gre_id=1)
        self.driver._add_allocation(session, set([2]))
        with testtools.ExpectedException(sa_exc.NoResultFound):
            _get_allocation(session, 1)


class GreTypeMultiRangeTest(test_type_vxlan.TunnelTypeMultiRangeTestMixin,
                           testlib_api.SqlTestCase):
    DRIVER_CLASS = type_gre.GreTypeDriver
