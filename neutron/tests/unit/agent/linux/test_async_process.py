# Copyright 2013 Red Hat, Inc.
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

import contextlib

import eventlet.event
import eventlet.queue
import eventlet.timeout
import mock
import testtools

from neutron.agent.linux import async_process
from neutron.agent.linux import utils
from neutron.tests import base


class TestAsyncProcess(base.BaseTestCase):

    def setUp(self):
        super(TestAsyncProcess, self).setUp()
        self.proc = async_process.AsyncProcess(['fake'])

    def test_construtor_raises_exception_for_negative_respawn_interval(self):
        with testtools.ExpectedException(ValueError):
            async_process.AsyncProcess(['fake'], respawn_interval=-1)

    def test__spawn(self):
        expected_process = 'Foo'
        proc = self.proc
        with mock.patch.object(utils, 'create_process') as mock_create_process:
            mock_create_process.return_value = [expected_process, None]
            with mock.patch('eventlet.spawn') as mock_spawn:
                proc._spawn()

        self.assertIsInstance(proc._kill_event, eventlet.event.Event)
        self.assertEqual(proc._process, expected_process)
        mock_spawn.assert_has_calls([
            mock.call(proc._watch_process,
                      proc._read_stdout,
                      proc._kill_event),
            mock.call(proc._watch_process,
                      proc._read_stderr,
                      proc._kill_event),
        ])
        self.assertEqual(len(proc._watchers), 2)

    def test__handle_process_error_kills_with_respawn(self):
        with mock.patch.object(self.proc, '_kill') as kill:
            self.proc._handle_process_error()

        kill.assert_has_calls([mock.call(respawning=False)])

    def test__handle_process_error_kills_without_respawn(self):
        self.proc.respawn_interval = 1
        with mock.patch.object(self.proc, '_kill') as kill:
            with mock.patch.object(self.proc, '_spawn') as spawn:
                with mock.patch('eventlet.sleep') as sleep:
                    self.proc._handle_process_error()

        kill.assert_has_calls([mock.call(respawning=True)])
        sleep.assert_has_calls([mock.call(self.proc.respawn_interval)])
        spawn.assert_called_once_with()

    def _test__watch_process(self, callback, kill_event):
        self.proc._kill_event = kill_event
        # Ensure the test times out eventually if the watcher loops endlessly
        with eventlet.timeout.Timeout(5):
            with mock.patch.object(self.proc,
                                   '_handle_process_error') as func:
                self.proc._watch_process(callback, kill_event)

        if not kill_event.ready():
            func.assert_called_once_with()

    def test__watch_process_exits_on_callback_failure(self):
        self._test__watch_process(lambda: False, eventlet.event.Event())

    def test__watch_process_exits_on_exception(self):
        def foo():
            raise Exception('Error!')
        self._test__watch_process(foo, eventlet.event.Event())

    def test__watch_process_exits_on_sent_kill_event(self):
        kill_event = eventlet.event.Event()
        kill_event.send()
        self._test__watch_process(None, kill_event)

    def _test_read_output_queues_and_returns_result(self, output):
        queue = eventlet.queue.LightQueue()
        mock_stream = mock.Mock()
        with mock.patch.object(mock_stream, 'readline') as mock_readline:
            mock_readline.return_value = output
            result = self.proc._read(mock_stream, queue)

        if output:
            self.assertEqual(output, result)
            self.assertEqual(output, queue.get_nowait())
        else:
            self.assertFalse(result)
            self.assertTrue(queue.empty())

    def test__read_queues_and_returns_output(self):
        self._test_read_output_queues_and_returns_result('foo')

    def test__read_returns_none_for_missing_output(self):
        self._test_read_output_queues_and_returns_result('')

    def test_start_raises_exception_if_process_already_started(self):
        self.proc._kill_event = True
        with testtools.ExpectedException(async_process.AsyncProcessException):
            self.proc.start()

    def test_start_invokes__spawn(self):
        with mock.patch.object(self.proc, '_spawn') as mock_start:
            self.proc.start()

        mock_start.assert_called_once_with()

    def test__iter_queue_returns_empty_list_for_empty_queue(self):
        result = list(self.proc._iter_queue(eventlet.queue.LightQueue(),
                                            False))
        self.assertEqual(result, [])

    def test__iter_queue_returns_queued_data(self):
        queue = eventlet.queue.LightQueue()
        queue.put('foo')
        result = list(self.proc._iter_queue(queue, False))
        self.assertEqual(result, ['foo'])

    def _test_iter_output_calls_iter_queue_on_output_queue(self, output_type):
        expected_value = 'foo'
        with mock.patch.object(self.proc, '_iter_queue') as mock_iter_queue:
            mock_iter_queue.return_value = expected_value
            target_func = getattr(self.proc, 'iter_%s' % output_type, None)
            value = target_func()

        self.assertEqual(value, expected_value)
        queue = getattr(self.proc, '_%s_lines' % output_type, None)
        mock_iter_queue.assert_called_with(queue, False)

    def test_iter_stdout(self):
        self._test_iter_output_calls_iter_queue_on_output_queue('stdout')

    def test_iter_stderr(self):
        self._test_iter_output_calls_iter_queue_on_output_queue('stderr')

    def _test__kill(self, respawning, pid=None):
        with contextlib.nested(
                mock.patch.object(self.proc, '_kill_event'),
                mock.patch.object(utils, 'get_root_helper_child_pid',
                                  return_value=pid),
                mock.patch.object(self.proc, '_kill_process'),
                mock.patch.object(self.proc, '_process')) as (
                    mock_kill_event,
                    mock_get_child_pid,
                    mock_kill_process,
                    mock_process):
            self.proc._kill(respawning)

            if respawning:
                self.assertIsNotNone(self.proc._kill_event)
            else:
                self.assertIsNone(self.proc._kill_event)

        mock_kill_event.send.assert_called_once_with()
        if pid:
            mock_kill_process.assert_called_once_with(pid)

    def test__kill_when_respawning_does_not_clear_kill_event(self):
        self._test__kill(True)

    def test__kill_when_not_respawning_clears_kill_event(self):
        self._test__kill(False)

    def test__kill_targets_process_for_pid(self):
        self._test__kill(False, pid='1')

    def _test__kill_process(self, pid, expected, exception_message=None):
        self.proc.run_as_root = True
        if exception_message:
            exc = RuntimeError(exception_message)
        else:
            exc = None
        with mock.patch.object(utils, 'execute',
                               side_effect=exc) as mock_execute:
            actual = self.proc._kill_process(pid)

        self.assertEqual(expected, actual)
        mock_execute.assert_called_with(['kill', '-9', pid],
                                        run_as_root=self.proc.run_as_root)

    def test__kill_process_returns_true_for_valid_pid(self):
        self._test__kill_process('1', True)

    def test__kill_process_returns_true_for_stale_pid(self):
        self._test__kill_process('1', True, 'No such process')

    def test__kill_process_returns_false_for_execute_exception(self):
        self._test__kill_process('1', False, 'Invalid')

    def test_stop_calls_kill(self):
        self.proc._kill_event = True
        with mock.patch.object(self.proc, '_kill') as mock_kill:
            self.proc.stop()
        mock_kill.assert_called_once_with()

    def test_stop_raises_exception_if_already_started(self):
        with testtools.ExpectedException(async_process.AsyncProcessException):
            self.proc.stop()
