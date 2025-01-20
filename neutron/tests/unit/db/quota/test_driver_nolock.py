# Copyright (c) 2021 Red Hat, Inc.
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

import itertools

import netaddr
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api

from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import models_v2
from neutron.db.quota import api as quota_api
from neutron.db.quota import driver_nolock
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import quota as quota_obj
from neutron.objects import subnet as subnet_obj
from neutron.quota import resource as quota_resource
from neutron.tests.unit.db.quota import test_driver


class FakePlugin(base_plugin.NeutronDbPluginV2,
                 driver_nolock.DbQuotaNoLockDriver):
    """A fake plugin class containing all DB methods."""


class TestDbQuotaDriverNoLock(test_driver.TestDbQuotaDriver):

    def setUp(self):
        super().setUp()
        self.plugin = FakePlugin()
        self.quota_driver = driver_nolock.DbQuotaNoLockDriver()

    @staticmethod
    def _cleanup_timeout(previous_value):
        quota_api.RESERVATION_EXPIRATION_TIMEOUT = previous_value

    def test__remove_expired_reservations(self):
        for project, resource in itertools.product(self.projects,
                                                   self.resources):
            deltas = {resource: 1}
            with db_api.CONTEXT_WRITER.using(self.context):
                quota_api.create_reservation(self.context, project, deltas)

        # Initial check: the reservations are correctly created.
        for project in self.projects:
            for res in quota_obj.Reservation.get_objects(self.context,
                                                         project_id=project):
                self.assertEqual(1, len(res.resource_deltas))
                delta = res.resource_deltas[0]
                self.assertEqual(1, delta.amount)
                self.assertIn(delta.resource, self.resources)

        # Delete the expired reservations and check.
        # NOTE(ralonsoh): the timeout is set to -121 to force the deletion
        # of all created reservations, including those ones created in this
        # test. The value of 121 overcomes the 120 seconds of default
        # expiration time a reservation has.
        timeout = quota_api.RESERVATION_EXPIRATION_TIMEOUT
        quota_api.RESERVATION_EXPIRATION_TIMEOUT = -(timeout + 1)
        self.addCleanup(self._cleanup_timeout, timeout)
        self.quota_driver._remove_expired_reservations()
        res = quota_obj.Reservation.get_objects(self.context)
        self.assertEqual([], res)

    def test_get_detailed_project_quotas_resource(self):
        user_ctx = context.Context(user_id=self.project_1,
                                   project_id=self.project_1)
        tracked_resource = quota_resource.TrackedResource(
            'network', models_v2.Network, 'quota_network')
        res = {'network': tracked_resource}
        self.plugin.update_quota_limit(user_ctx, self.project_1, 'network', 20)
        self.quota_driver.make_reservation(user_ctx, self.project_1, res,
                                           {'network': 5}, self.plugin)
        with db_api.CONTEXT_WRITER.using(user_ctx):
            network_obj.Network(user_ctx, project_id=self.project_1).create()

        detailed_quota = self.plugin.get_detailed_project_quotas(
            user_ctx, res, self.project_1)
        reference = {'network': {'limit': 20, 'used': 1, 'reserved': 5}}
        self.assertEqual(reference, detailed_quota)

    @staticmethod
    def _create_tracked_resources():
        return {
            'network': quota_resource.TrackedResource(
                'network', models_v2.Network, 'quota_network'),
            'subnet': quota_resource.TrackedResource(
                'subnet', models_v2.Subnet, 'quota_subnet'),
            'port': quota_resource.TrackedResource(
                'port', models_v2.Port, 'quota_port'),
        }

    def test_get_detailed_project_quotas_multiple_resource(self):
        resources = self._create_tracked_resources()
        for project_id in self.projects:
            user_ctx = context.Context(user_id=project_id,
                                       project_id=project_id)
            self.plugin.update_quota_limit(
                user_ctx, project_id, 'network', 101)
            self.plugin.update_quota_limit(user_ctx, project_id, 'subnet', 102)
            self.plugin.update_quota_limit(user_ctx, project_id, 'port', 103)

            with db_api.CONTEXT_WRITER.using(user_ctx):
                net = network_obj.Network(
                    user_ctx, project_id=project_id)
                net.create()
                subnet_obj.Subnet(
                    user_ctx, project_id=project_id, network_id=net.id,
                    ip_version=constants.IP_VERSION_4,
                    cidr=netaddr.IPNetwork('1.2.3.0/24')).create()
                port_obj.Port(
                    user_ctx, project_id=project_id,
                    network_id=net.id,
                    mac_address=netaddr.EUI('ca:fe:ca:fe:ca:fe'),
                    admin_state_up=False, status='DOWN', device_id='',
                    device_owner='').create()

        reference = {'network': {'limit': 101, 'used': 1, 'reserved': 0},
                     'subnet': {'limit': 102, 'used': 1, 'reserved': 0},
                     'port': {'limit': 103, 'used': 1, 'reserved': 0}}
        for project_id in self.projects:
            user_ctx = context.Context(user_id=project_id,
                                       project_id=project_id)
            returned = self.plugin.get_detailed_project_quotas(
                user_ctx, resources, project_id)
            self.assertEqual(reference, returned)
