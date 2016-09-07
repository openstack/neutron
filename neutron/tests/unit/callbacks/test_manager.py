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
from oslo_db import exception as db_exc

from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import manager
from neutron.callbacks import resources
from neutron.tests import base


class ObjectWithCallback(object):

    def __init__(self):
        self.counter = 0

    def callback(self, *args, **kwargs):
        self.counter += 1


class GloriousObjectWithCallback(ObjectWithCallback):
    pass


def callback_1(*args, **kwargs):
    callback_1.counter += 1
callback_id_1 = manager._get_id(callback_1)


def callback_2(*args, **kwargs):
    callback_2.counter += 1
callback_id_2 = manager._get_id(callback_2)


def callback_raise(*args, **kwargs):
    raise Exception()


def callback_raise_retriable(*args, **kwargs):
    raise db_exc.DBDeadlock()


class CallBacksManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(CallBacksManagerTestCase, self).setUp()
        self.manager = manager.CallbacksManager()
        callback_1.counter = 0
        callback_2.counter = 0

    def test_subscribe(self):
        self.manager.subscribe(
            callback_1, resources.PORT, events.BEFORE_CREATE)
        self.assertIsNotNone(
            self.manager._callbacks[resources.PORT][events.BEFORE_CREATE])
        self.assertIn(callback_id_1, self.manager._index)

    def test_subscribe_unknown(self):
        self.manager.subscribe(
            callback_1, 'my_resource', 'my-event')
        self.assertIsNotNone(
            self.manager._callbacks['my_resource']['my-event'])
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

    def test_unsubscribe_during_iteration(self):
        unsub = lambda r, e, *a, **k: self.manager.unsubscribe(unsub, r, e)
        self.manager.subscribe(unsub, resources.PORT,
                               events.BEFORE_CREATE)
        self.manager.notify(resources.PORT, events.BEFORE_CREATE, mock.ANY)
        self.assertNotIn(unsub, self.manager._index)

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

    def test_feebly_referenced_callback(self):
        self.manager.subscribe(lambda *x, **y: None, resources.PORT,
                               events.BEFORE_CREATE)
        self.manager.notify(resources.PORT, events.BEFORE_CREATE, mock.ANY)

    def test_notify_with_exception(self):
        with mock.patch.object(self.manager, '_notify_loop') as n:
            n.return_value = ['error']
            self.assertRaises(exceptions.CallbackFailure,
                              self.manager.notify,
                              mock.ANY, events.BEFORE_CREATE,
                              'trigger', params={'a': 1})
            expected_calls = [
                mock.call(mock.ANY, 'before_create',
                          'trigger', params={'a': 1}),
                mock.call(mock.ANY, 'abort_create',
                          'trigger', params={'a': 1})
            ]
            n.assert_has_calls(expected_calls)

    def test_notify_handle_exception(self):
        self.manager.subscribe(
            callback_raise, resources.PORT, events.BEFORE_CREATE)
        e = self.assertRaises(exceptions.CallbackFailure, self.manager.notify,
                              resources.PORT, events.BEFORE_CREATE, self)
        self.assertIsInstance(e.errors[0], exceptions.NotificationError)

    def test_notify_handle_retriable_exception(self):
        self.manager.subscribe(
            callback_raise_retriable, resources.PORT, events.BEFORE_CREATE)
        self.assertRaises(db_exc.RetryRequest, self.manager.notify,
                          resources.PORT, events.BEFORE_CREATE, self)

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

    @mock.patch("neutron.callbacks.manager.LOG")
    def test__notify_loop_skip_log_errors(self, _logger):
        self.manager.subscribe(
            callback_raise, resources.PORT, events.BEFORE_CREATE)
        self.manager.subscribe(
            callback_raise, resources.PORT, events.PRECOMMIT_CREATE)
        self.manager._notify_loop(
            resources.PORT, events.BEFORE_CREATE, mock.ANY)
        self.manager._notify_loop(
            resources.PORT, events.PRECOMMIT_CREATE, mock.ANY)
        self.assertFalse(_logger.exception.call_count)
        self.assertTrue(_logger.error.call_count)

    def test_object_instances_as_subscribers(self):
        """Ensures that the manager doesn't think these are equivalent."""
        a = GloriousObjectWithCallback()
        b = ObjectWithCallback()
        c = ObjectWithCallback()
        for o in (a, b, c):
            self.manager.subscribe(
                o.callback, resources.PORT, events.BEFORE_CREATE)
            # ensure idempotency remains for a single object
            self.manager.subscribe(
                o.callback, resources.PORT, events.BEFORE_CREATE)
        self.manager.notify(resources.PORT, events.BEFORE_CREATE, mock.ANY)
        self.assertEqual(1, a.counter)
        self.assertEqual(1, b.counter)
        self.assertEqual(1, c.counter)
