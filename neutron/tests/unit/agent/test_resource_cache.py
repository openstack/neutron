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

from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import context

from neutron.agent import resource_cache
from neutron.api.rpc.callbacks import events as events_rpc
from neutron.tests import base


class OVOLikeThing(object):
    def __init__(self, id, revision_number=10, **kwargs):
        self.id = id
        self.fields = ['id', 'revision_number']
        self.revision_number = revision_number
        for k, v in kwargs.items():
            self.fields.append(k)
            setattr(self, k, v)

    def to_dict(self):
        return {f: getattr(self, f) for f in self.fields}

    def get(self, k):
        return getattr(self, k, None)


class RemoteResourceCacheTestCase(base.BaseTestCase):
    def setUp(self):
        super(RemoteResourceCacheTestCase, self).setUp()
        rtypes = ['duck', 'goose']
        self.goose = OVOLikeThing(1)
        self.duck = OVOLikeThing(2)
        self.ctx = context.get_admin_context()
        self.rcache = resource_cache.RemoteResourceCache(rtypes)
        self._pullmock = mock.patch.object(self.rcache, '_puller').start()

    def test_get_resource_by_id(self):
        self.rcache.record_resource_update(self.ctx, 'goose', self.goose)
        self.assertEqual(self.goose,
                         self.rcache.get_resource_by_id('goose', 1))
        self.assertIsNone(self.rcache.get_resource_by_id('goose', 2))

    def test__flood_cache_for_query_pulls_once(self):
        resources = [OVOLikeThing(66), OVOLikeThing(67)]
        received_kw = []
        receiver = lambda r, e, t, payload: \
            received_kw.append(payload)
        registry.subscribe(receiver, 'goose', events.AFTER_UPDATE)

        self._pullmock.bulk_pull.side_effect = [
            resources,
            [resources[0]],
            [resources[1]],
            [resources[1]]
        ]

        self.rcache._flood_cache_for_query('goose', id=(66, 67),
                                           name=('a', 'b'))
        self._pullmock.bulk_pull.assert_called_once_with(
            mock.ANY, 'goose',
            filter_kwargs={'id': (66, 67), 'name': ('a', 'b')})

        self._pullmock.bulk_pull.reset_mock()
        self.rcache._flood_cache_for_query('goose', id=(66, ), name=('a', ))
        self.assertFalse(self._pullmock.called)
        self.rcache._flood_cache_for_query('goose', id=(67, ), name=('b', ))
        self.assertFalse(self._pullmock.called)

        # querying by just ID should trigger a new call since ID+name is a more
        # specific query
        self.rcache._flood_cache_for_query('goose', id=(67, ))
        self._pullmock.bulk_pull.assert_called_once_with(
            mock.ANY, 'goose', filter_kwargs={'id': (67, )})

        self.assertCountEqual(
            resources, [rec.latest_state for rec in received_kw])

    def test_bulk_pull_doesnt_wipe_out_newer_data(self):
        self.rcache.record_resource_update(
            self.ctx, 'goose', OVOLikeThing(1, revision_number=5))
        updated = OVOLikeThing(1)
        updated.revision_number = 1  # older revision number
        self._pullmock.bulk_pull.return_value = [updated]
        self.rcache._flood_cache_for_query('goose', id=(1,),)
        self.assertEqual(
             5, self.rcache.get_resource_by_id('goose', 1).revision_number)

    def test_get_resources(self):
        geese = [OVOLikeThing(3, size='large'), OVOLikeThing(5, size='medium'),
                 OVOLikeThing(4, size='large'), OVOLikeThing(6, size='small')]
        for goose in geese:
            self.rcache.record_resource_update(self.ctx, 'goose', goose)
        is_large = {'size': ('large', )}
        is_small = {'size': ('small', )}
        self.assertCountEqual([geese[0], geese[2]],
                              self.rcache.get_resources('goose', is_large))
        self.assertCountEqual([geese[3]],
                              self.rcache.get_resources('goose', is_small))

    def test_match_resources_with_func(self):
        geese = [OVOLikeThing(3, size='large'), OVOLikeThing(5, size='medium'),
                 OVOLikeThing(4, size='xlarge'), OVOLikeThing(6, size='small')]
        for goose in geese:
            self.rcache.record_resource_update(self.ctx, 'goose', goose)
        has_large = lambda o: 'large' in o.size
        self.assertCountEqual([geese[0], geese[2]],
                              self.rcache.match_resources_with_func('goose',
                                                                    has_large))

    def test__is_stale(self):
        goose = OVOLikeThing(3, size='large')
        self.rcache.record_resource_update(self.ctx, 'goose', goose)
        # same revision id is not considered stale
        updated = OVOLikeThing(3, size='large')
        self.assertFalse(self.rcache._is_stale('goose', updated))
        updated.revision_number = 0
        self.assertTrue(self.rcache._is_stale('goose', updated))
        updated.revision_number = 200
        self.assertFalse(self.rcache._is_stale('goose', updated))
        # once deleted, all updates are stale
        self.rcache.record_resource_delete(self.ctx, 'goose', 3)
        self.assertTrue(self.rcache._is_stale('goose', updated))

    def test_record_resource_update(self):
        received_kw = []
        receiver = lambda r, e, t, payload: \
            received_kw.append(payload)
        registry.subscribe(receiver, 'goose', events.AFTER_UPDATE)
        self.rcache.record_resource_update(self.ctx, 'goose',
                                           OVOLikeThing(3, size='large'))
        self.assertEqual(1, len(received_kw))
        self.assertIsNone(received_kw[0].states[0])
        # another update with no changed fields results in no callback
        self.rcache.record_resource_update(self.ctx, 'goose',
                                           OVOLikeThing(3, size='large',
                                                        revision_number=100))
        self.assertEqual(1, len(received_kw))
        self.rcache.record_resource_update(self.ctx, 'goose',
                                           OVOLikeThing(3, size='small',
                                                        revision_number=101))
        self.assertEqual(2, len(received_kw))
        self.assertEqual('large', received_kw[1].states[0].size)
        self.assertEqual('small', received_kw[1].latest_state.size)
        self.assertEqual(set(['size']),
                         received_kw[1].metadata['changed_fields'])

    def test_record_resource_delete(self):
        received_kw = []
        receiver = lambda r, e, t, payload: \
            received_kw.append(payload)
        registry.subscribe(receiver, 'goose', events.AFTER_DELETE)
        self.rcache.record_resource_update(self.ctx, 'goose',
                                           OVOLikeThing(3, size='large'))
        self.rcache.record_resource_delete(self.ctx, 'goose', 3)
        self.assertEqual(1, len(received_kw))
        self.assertEqual(3, received_kw[0].states[0].id)
        self.assertEqual(3, received_kw[0].resource_id)
        # deletes of non-existing cache items are still honored
        self.rcache.record_resource_delete(self.ctx, 'goose', 4)
        self.assertEqual(2, len(received_kw))
        self.assertIsNone(received_kw[1].states[0])
        self.assertEqual(4, received_kw[1].resource_id)

    def test_record_resource_delete_ignores_dups(self):
        received_kw = []
        receiver = lambda r, e, t, payload: \
            received_kw.append(payload)
        registry.subscribe(receiver, 'goose', events.AFTER_DELETE)
        self.rcache.record_resource_delete(self.ctx, 'goose', 3)
        self.assertEqual(1, len(received_kw))
        self.rcache.record_resource_delete(self.ctx, 'goose', 4)
        self.assertEqual(2, len(received_kw))
        self.rcache.record_resource_delete(self.ctx, 'goose', 3)
        self.assertEqual(2, len(received_kw))

    def test_resource_change_handler(self):
        with mock.patch.object(resource_cache.RemoteResourceWatcher,
                               '_init_rpc_listeners'):
            watch = resource_cache.RemoteResourceWatcher(self.rcache)
        geese = [OVOLikeThing(3, size='large'), OVOLikeThing(5, size='medium'),
                 OVOLikeThing(4, size='large'), OVOLikeThing(6, size='small')]
        watch.resource_change_handler(self.ctx, 'goose', geese,
                                      events_rpc.UPDATED)
        for goose in geese:
            self.assertEqual(goose,
                             self.rcache.get_resource_by_id('goose', goose.id))
        watch.resource_change_handler(self.ctx, 'goose', geese,
                                      events_rpc.DELETED)
        for goose in geese:
            self.assertIsNone(
                self.rcache.get_resource_by_id('goose', goose.id))
