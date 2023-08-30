# Copyright 2019 Red Hat, Inc.
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

import datetime
import time
from unittest import mock

from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy.orm import exc

from neutron.db.models import ovn as ovn_models
from neutron.db import ovn_hash_ring_db
from neutron.tests.unit import testlib_api

HASH_RING_TEST_GROUP = 'test_group'


class TestHashRing(testlib_api.SqlTestCaseLight):

    def setUp(self):
        super(TestHashRing, self).setUp()
        self.admin_ctx = context.get_admin_context()
        self.addCleanup(self._delete_objs)

    def _delete_objs(self):
        with db_api.CONTEXT_WRITER.using(self.admin_ctx):
            self.admin_ctx.session.query(
                ovn_models.OVNRevisionNumbers).delete()

    def _get_node_row(self, node_uuid):
        try:
            with db_api.CONTEXT_WRITER.using(self.admin_ctx):
                node = self.admin_ctx.session.query(
                    ovn_models.OVNHashRing).filter_by(
                    node_uuid=node_uuid).one()
            # When a record is created, the difference between "created_at" and
            # "updated_at" should be tiny, just some microseconds.
            if (node.updated_at - node.created_at).total_seconds() < 0.01:
                node.updated_at = node.created_at
            # Ignore miliseconds
            node.created_at = node.created_at.replace(microsecond=0)
            node.updated_at = node.updated_at.replace(microsecond=0)
            return node
        except exc.NoResultFound:
            return

    def _add_nodes_and_assert_exists(self, count=1,
                                     group_name=HASH_RING_TEST_GROUP):
        nodes = []
        for i in range(count):
            node_uuid = ovn_hash_ring_db.add_node(self.admin_ctx, group_name)
            self.assertIsNotNone(self._get_node_row(node_uuid))
            nodes.append(node_uuid)
        return nodes

    def test_add_node(self):
        self._add_nodes_and_assert_exists()

    def test_remove_nodes_from_host(self):
        nodes = self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        with mock.patch.object(ovn_hash_ring_db, 'CONF') as mock_conf:
            mock_conf.host = 'another-host-' + uuidutils.generate_uuid()
            another_host_node = self._add_nodes_and_assert_exists()[0]

        ovn_hash_ring_db.remove_nodes_from_host(self.admin_ctx,
                                                HASH_RING_TEST_GROUP)
        # Assert that all nodes from that host have been removed
        for n in nodes:
            self.assertIsNone(self._get_node_row(n))

        # Assert that the node from another host wasn't removed
        self.assertIsNotNone(self._get_node_row(another_host_node))

    def test_touch_nodes_from_host(self):
        nodes = self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        with mock.patch.object(ovn_hash_ring_db, 'CONF') as mock_conf:
            mock_conf.host = 'another-host-' + uuidutils.generate_uuid()
            another_host_node = self._add_nodes_and_assert_exists()[0]

        # Assert that updated_at isn't updated yet
        for node in nodes:
            node_db = self._get_node_row(node)
            self.assertEqual(node_db.created_at, node_db.updated_at)

        # Assert the same for the node from another host
        node_db = self._get_node_row(another_host_node)
        self.assertEqual(node_db.created_at, node_db.updated_at)

        # Touch the nodes from our host
        time.sleep(1)
        ovn_hash_ring_db.touch_nodes_from_host(self.admin_ctx,
                                               HASH_RING_TEST_GROUP)

        # Assert that updated_at is now updated
        for node in nodes:
            node_db = self._get_node_row(node)
            self.assertGreater(node_db.updated_at, node_db.created_at)

        # Assert that the node from another host hasn't been touched
        # (updated_at is not updated)
        node_db = self._get_node_row(another_host_node)
        self.assertEqual(node_db.created_at, node_db.updated_at)

    def test_active_nodes(self):
        self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        with mock.patch.object(ovn_hash_ring_db, 'CONF') as mock_conf:
            mock_conf.host = 'another-host-' + uuidutils.generate_uuid()
            another_host_node = self._add_nodes_and_assert_exists()[0]

        # Assert all nodes are active (within 60 seconds)
        self.assertEqual(4, len(ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP)))

        # Subtract 60 seconds from utcnow() and touch the nodes from our host
        time.sleep(1)
        fake_utcnow = timeutils.utcnow() - datetime.timedelta(seconds=60)
        with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
            mock_utcnow.return_value = fake_utcnow
            ovn_hash_ring_db.touch_nodes_from_host(self.admin_ctx,
                                                   HASH_RING_TEST_GROUP)

        # Now assert that all nodes from our host are seeing as offline.
        # Only the node from another host should be active
        active_nodes = ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP)
        self.assertEqual(1, len(active_nodes))
        self.assertEqual(another_host_node, active_nodes[0].node_uuid)

    def test_active_nodes_from_host(self):
        self._add_nodes_and_assert_exists(count=3)

        # Add another node from a different host
        another_host_id = 'another-host-52359446-c366'
        with mock.patch.object(ovn_hash_ring_db, 'CONF') as mock_conf:
            mock_conf.host = another_host_id
            self._add_nodes_and_assert_exists()

        # Assert only the 3 nodes from this host is returned
        active_nodes = ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP,
            from_host=True)
        self.assertEqual(3, len(active_nodes))
        self.assertNotIn(another_host_id, active_nodes)

    def test_touch_node(self):
        nodes = self._add_nodes_and_assert_exists(count=3)

        # Assert no nodes were updated yet
        for node in nodes:
            node_db = self._get_node_row(node)
            self.assertEqual(node_db.created_at, node_db.updated_at)

        # Touch one of the nodes
        time.sleep(1)
        ovn_hash_ring_db.touch_node(self.admin_ctx, nodes[0])

        # Assert it has been updated
        node_db = self._get_node_row(nodes[0])
        self.assertGreater(node_db.updated_at, node_db.created_at)

        # Assert the other two nodes hasn't been updated
        for node in nodes[1:]:
            node_db = self._get_node_row(node)
            self.assertEqual(node_db.created_at, node_db.updated_at)

    def test_active_nodes_different_groups(self):
        another_group = 'another_test_group'
        self._add_nodes_and_assert_exists(count=3)
        self._add_nodes_and_assert_exists(count=2, group_name=another_group)

        active_nodes = ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP)
        self.assertEqual(3, len(active_nodes))
        for node in active_nodes:
            self.assertEqual(HASH_RING_TEST_GROUP, node.group_name)

        active_nodes = ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=another_group)
        self.assertEqual(2, len(active_nodes))
        for node in active_nodes:
            self.assertEqual(another_group, node.group_name)

    def test_remove_nodes_from_host_different_groups(self):
        another_group = 'another_test_group'
        group1 = self._add_nodes_and_assert_exists(count=3)
        group2 = self._add_nodes_and_assert_exists(
            count=2, group_name=another_group)

        ovn_hash_ring_db.remove_nodes_from_host(self.admin_ctx,
                                                HASH_RING_TEST_GROUP)
        # Assert that all nodes from that group have been removed
        for node in group1:
            self.assertIsNone(self._get_node_row(node))

        # Assert that all nodes from a different group are intact
        for node in group2:
            self.assertIsNotNone(self._get_node_row(node))

    def test_touch_nodes_from_host_different_groups(self):
        another_group = 'another_test_group'
        group1 = self._add_nodes_and_assert_exists(count=3)
        group2 = self._add_nodes_and_assert_exists(
            count=2, group_name=another_group)

        # Assert that updated_at isn't updated yet
        for node in group1 + group2:
            node_db = self._get_node_row(node)
            self.assertEqual(node_db.created_at, node_db.updated_at)

        # Touch the nodes from group1
        time.sleep(1)
        ovn_hash_ring_db.touch_nodes_from_host(self.admin_ctx,
                                               HASH_RING_TEST_GROUP)

        # Assert that updated_at was updated for group1
        for node in group1:
            node_db = self._get_node_row(node)
            self.assertGreater(node_db.updated_at, node_db.created_at)

        # Assert that updated_at wasn't updated for group2
        for node in group2:
            node_db = self._get_node_row(node)
            self.assertEqual(node_db.created_at, node_db.updated_at)

    def test_count_offline_nodes(self):
        self._add_nodes_and_assert_exists(count=3)

        # Assert no nodes are considered offline
        self.assertEqual(0, ovn_hash_ring_db.count_offline_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP))

        # Subtract 60 seconds from utcnow() and touch the nodes to make
        # them to appear offline
        fake_utcnow = timeutils.utcnow() - datetime.timedelta(seconds=60)
        with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
            mock_utcnow.return_value = fake_utcnow
            ovn_hash_ring_db.touch_nodes_from_host(self.admin_ctx,
                                                   HASH_RING_TEST_GROUP)

        # Now assert that all nodes from our host are seeing as offline
        self.assertEqual(3, ovn_hash_ring_db.count_offline_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP))

        # Touch the nodes again without faking utcnow()
        ovn_hash_ring_db.touch_nodes_from_host(self.admin_ctx,
                                               HASH_RING_TEST_GROUP)

        # Assert no nodes are considered offline
        self.assertEqual(0, ovn_hash_ring_db.count_offline_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP))

    def test_remove_node_by_uuid(self):
        self._add_nodes_and_assert_exists(count=3)

        active_nodes = ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP)
        self.assertEqual(3, len(active_nodes))

        node_to_remove = active_nodes[0].node_uuid
        ovn_hash_ring_db.remove_node_by_uuid(
                self.admin_ctx, node_to_remove)

        active_nodes = ovn_hash_ring_db.get_active_nodes(
            self.admin_ctx, interval=60, group_name=HASH_RING_TEST_GROUP)
        self.assertEqual(2, len(active_nodes))
        self.assertNotIn(node_to_remove, [n.node_uuid for n in active_nodes])

    def test_cleanup_old_nodes(self):
        # Add 2 new nodes
        self._add_nodes_and_assert_exists(count=2)

        # Subtract 5 days from utcnow() and touch the nodes to make
        # them to appear stale
        fake_utcnow = timeutils.utcnow() - datetime.timedelta(days=5)
        with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
            mock_utcnow.return_value = fake_utcnow
            ovn_hash_ring_db.touch_nodes_from_host(self.admin_ctx,
                                                   HASH_RING_TEST_GROUP)

        # Add 3 new nodes
        self._add_nodes_and_assert_exists(count=3)

        # Assert we have 5 nodes in the hash ring
        self.assertEqual(5, ovn_hash_ring_db.count_nodes_from_host(
            self.admin_ctx, HASH_RING_TEST_GROUP))

        # Clean up the 2 stale nodes
        ovn_hash_ring_db.cleanup_old_nodes(self.admin_ctx, days=5)

        # Assert we only have 3 node entries after the clean up
        self.assertEqual(3, ovn_hash_ring_db.count_nodes_from_host(
            self.admin_ctx, HASH_RING_TEST_GROUP))
