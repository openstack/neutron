# Copyright 2015 OpenStack Foundation
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
import testtools

from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import manager
from neutron.callbacks import resources
from neutron.tests import base


def callback_1(*args, **kwargs):
    callback_1.counter += 1
callback_id_1 = manager._get_id(callback_1)


def callback_2(*args, **kwargs):
    callback_2.counter += 1
callback_id_2 = manager._get_id(callback_2)


def callback_raise(*args, **kwargs):
    raise Exception()


class CallBacksManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(CallBacksManagerTestCase, self).setUp()
        self.manager = manager.CallbacksManager()
        callback_1.counter = 0
        callback_2.counter = 0

    def test_subscribe_invalid_resource_raise(self):
        with testtools.ExpectedException(exceptions.Invalid):
            self.manager.subscribe(mock.ANY, 'foo_resource', mock.ANY)

    def test_subscribe_invalid_event_raise(self):
        self.assertRaises(exceptions.Invalid,
                  self.manager.subscribe,
                  mock.ANY, mock.ANY, 'foo_event')

    def test_subscribe(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.assertIsNotNone(
            self.manager._callbacks[resources.PORT][events.BEFORE_CREATE])
        self.assertIn(callback_id_1, self.manager._index)

    def test_subscribe_is_idempotent(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.assertEqual(
            1,
            len(self.manager._callbacks[resources.PORT][events.BEFORE_CREATE]))
        callbacks = self.manager._index[callback_id_1][resources.PORT]
        self.assertEqual(1, len(callbacks))

    def test_subscribe_multiple_callbacks(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_2, resources.PORT, events.BEFORE_CREATE)
        self.assertEqual(2, len(self.manager._index))
        self.assertEqual(
            2,
            len(self.manager._callbacks[resources.PORT][events.BEFORE_CREATE]))

    def test_unsubscribe(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.unsubscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.assertNotIn(
            callback_id_1,
            self.manager._callbacks[resources.PORT][events.BEFORE_CREATE])
        self.assertNotIn(callback_id_1, self.manager._index)

    def test_unsubscribe_unknown_callback(self):
        self.manager.subscribe(
            callback_2, resources.PORT, events.BEFORE_CREATE)
        self.manager.unsubscribe(callback_1, mock.ANY, mock.ANY)
        self.assertEqual(1, len(self.manager._index))

    def test_unsubscribe_is_idempotent(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.unsubscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.unsubscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.assertNotIn(callback_id_1, self.manager._index)
        self.assertNotIn(callback_id_1,
            self.manager._callbacks[resources.PORT][events.BEFORE_CREATE])

    def test_unsubscribe_by_resource(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_DELETE)
        self.manager.subscribe(
            callback_2, resources.PORT, events.BEFORE_DELETE)
        self.manager.unsubscribe_by_resource(callback_1, resources.PORT)
        self.assertNotIn(
            callback_id_1,
            self.manager._callbacks[resources.PORT][events.BEFORE_CREATE])
        self.assertIn(
            callback_id_2,
            self.manager._callbacks[resources.PORT][events.BEFORE_DELETE])
        self.assertNotIn(callback_id_1, self.manager._index)

    def test_unsubscribe_all(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_DELETE)
        self.manager.subscribe(
            callback_1, resources.ROUTER, events.BEFORE_CREATE)
        self.manager.unsubscribe_all(callback_1)
        self.assertNotIn(
            callback_id_1,
            self.manager._callbacks[resources.PORT][events.BEFORE_CREATE])
        self.assertNotIn(callback_id_1, self.manager._index)

    def test_notify_none(self):
        self.manager.notify(resources.PORT, events.BEFORE_CREATE, mock.ANY)
        self.assertEqual(0, callback_1.counter)
        self.assertEqual(0, callback_2.counter)

    def test_notify_with_exception(self):
        with mock.patch.object(self.manager, '_notify_loop') as n:
            n.return_value = ['error']
            self.assertRaises(exceptions.CallbackFailure,
                              self.manager.notify,
                              mock.ANY, events.BEFORE_CREATE, mock.ANY)
            expected_calls = [
                mock.call(mock.ANY, 'before_create', mock.ANY),
                mock.call(mock.ANY, 'abort_create', mock.ANY)
            ]
            n.assert_has_calls(expected_calls)

    def test_notify_handle_exception(self):
        self.manager.subscribe(
            callback_raise, resources.PORT, events.BEFORE_CREATE)
        e = self.assertRaises(exceptions.CallbackFailure, self.manager.notify,
                              resources.PORT, events.BEFORE_CREATE, self)
        self.assertIsInstance(e.errors[0], exceptions.NotificationError)

    def test_notify_called_once_with_no_failures(self):
        with mock.patch.object(self.manager, '_notify_loop') as n:
            n.return_value = False
            self.manager.notify(resources.PORT, events.BEFORE_CREATE, mock.ANY)
            n.assert_called_once_with(
                resources.PORT, events.BEFORE_CREATE, mock.ANY)

    def test__notify_loop_single_event(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_2, resources.PORT, events.BEFORE_CREATE)
        self.manager._notify_loop(
            resources.PORT, events.BEFORE_CREATE, mock.ANY)
        self.assertEqual(1, callback_1.counter)
        self.assertEqual(1, callback_2.counter)

    def test__notify_loop_multiple_events(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_1, resources.ROUTER, events.BEFORE_DELETE)
        self.manager.subscribe(
            callback_2, resources.PORT, events.BEFORE_CREATE)
        self.manager._notify_loop(
            resources.PORT, events.BEFORE_CREATE, mock.ANY)
        self.manager._notify_loop(
            resources.ROUTER, events.BEFORE_DELETE, mock.ANY)
        self.assertEqual(2, callback_1.counter)
        self.assertEqual(1, callback_2.counter)
