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

import queue as python_queue
import signal
import subprocess  # nosec
import sys
import threading
from unittest import mock

import testtools

from neutron.agent.common import async_process
from neutron.agent.common import utils
from neutron.tests import base
from neutron.tests.unit.agent.linux import failing_process


class TestAsyncProcess(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.proc = async_process.AsyncProcess(['fake'])

    def test_construtor_raises_exception_for_negative_respawn_interval(self):
        with testtools.ExpectedException(ValueError):
            async_process.AsyncProcess(['fake'], respawn_interval=-1)

    def test__spawn(self):
        expected_process = 'Foo'
        proc = self.proc
        with mock.patch.object(utils, 'create_process') as mock_create_process:
            mock_create_process.return_value = [expected_process, None]
            with mock.patch('threading.Thread') as mock_thread:
                proc._spawn()

        self.assertTrue(self.proc._is_running)
        self.assertIsInstance(proc._kill_event, threading.Event)
        self.assertEqual(proc._process, expected_process)
        mock_thread.assert_has_calls([
            mock.call(target=proc._watch_process,
                      args=(proc._read_stdout,
                            proc._kill_event,
                            mock.ANY),
                      daemon=False),
            mock.call().start(),
            mock.call(target=proc._watch_process,
                      args=(proc._read_stderr,
                            proc._kill_event,
                            mock.ANY),
                      daemon=False),
            mock.call().start()
        ])
        self.assertEqual(len(proc._watchers), 2)

    def test__pid_none(self):
        pid = 1
        self.proc._pid = None
        with mock.patch.object(self.proc, '_process') as _process:
            with mock.patch.object(utils,
                                   'get_root_helper_child_pid') as func:
                func.return_value = pid
                self.assertEqual(self.proc.pid, pid)
                func.assert_called_once_with(_process.pid, ['fake'],
                                             run_as_root=False)
                self.assertEqual(self.proc._pid, pid)

    def test__pid_not_none(self):
        self.proc._pid = 1
        with mock.patch.object(self.proc, '_process'),\
                mock.patch.object(utils, 'get_root_helper_child_pid') as func:
            self.assertEqual(self.proc.pid, 1)
            func.assert_not_called()

    def test__handle_process_error_kills(self):
        self.proc.respawn_interval = 1

        for is_started in (True, False):
            self.proc._is_started = is_started
            with mock.patch.object(self.proc, '_kill') as kill:
                with mock.patch.object(self.proc, '_spawn') as spawn:
                    with mock.patch('time.sleep') as sleep:
                        self.proc._handle_process_error()

            kill.assert_has_calls([mock.call(signal.SIGKILL)])
            sleep.assert_has_calls([mock.call(self.proc.respawn_interval)])
            if is_started:
                spawn.assert_called_once_with()
            else:
                spawn.assert_not_called()

    def test__handle_process_error_no_crash_if_started(self):
        self.proc._is_running = True
        with mock.patch.object(self.proc, '_kill'):
            with mock.patch.object(self.proc, '_spawn') as mock_spawn:
                self.proc._handle_process_error()
                mock_spawn.assert_not_called()

    def _watch_process_exception(self):
        raise Exception('Error!')

    def _test__watch_process(self, callback, kill_event):
        self.proc._is_running = True
        self.proc._kill_event = kill_event

        thread_exit_event = threading.Event()

        with mock.patch.object(self.proc,
                               '_handle_process_error') as func:
            self.proc._watch_process(
                callback, kill_event, thread_exit_event)

        if not kill_event.is_set():
            func.assert_called_once_with()

    def test__watch_process_exits_on_callback_failure(self):
        self._test__watch_process(lambda: None, threading.Event())

    def test__watch_process_exits_on_exception(self):
        self._test__watch_process(self._watch_process_exception,
                                  threading.Event())
        thread_exit_event = threading.Event()
        with mock.patch.object(self.proc,
                               '_handle_process_error') as func:
            self.proc._watch_process(self._watch_process_exception,
                                     self.proc._kill_event,
                                     thread_exit_event)
            func.assert_not_called()

    def test__watch_process_exits_on_sent_kill_event(self):
        kill_event = threading.Event()
        kill_event.set()
        self._test__watch_process(None, kill_event)

    def _test_read_output_queues_and_returns_result(self, output):
        queue = python_queue.Queue()
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
        self.proc._is_running = True
        with testtools.ExpectedException(async_process.AsyncProcessException):
            self.proc.start()

    def test_start_invokes__spawn(self):
        with mock.patch.object(self.proc, '_spawn') as mock_start:
            self.proc.start()

        mock_start.assert_called_once_with()

    def test__iter_queue_returns_empty_list_for_empty_queue(self):
        result = list(self.proc._iter_queue(python_queue.Queue(),
                                            False))
        self.assertEqual([], result)

    def test__iter_queue_returns_queued_data(self):
        queue = python_queue.Queue()
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

    def test__kill_targets_process_for_pid(self):
        pid = 1

        with mock.patch.object(self.proc, '_kill_event'
                               ) as mock_kill_event,\
                mock.patch.object(utils, 'get_root_helper_child_pid',
                                  return_value=pid),\
                mock.patch.object(self.proc, '_kill_process_and_wait'
                                  ) as mock_kill_process_and_wait,\
                mock.patch.object(self.proc, '_process'):
            self.proc._kill(signal.SIGKILL)

            self.assertIsNone(self.proc._kill_event)
            self.assertFalse(self.proc._is_running)
            self.assertIsNone(self.proc._pid)

        mock_kill_event.set.assert_called_once_with()
        if pid:
            mock_kill_process_and_wait.assert_called_once_with(
                pid, signal.SIGKILL, None)

    def _test__kill_process_and_wait(self, pid, expected,
                                     exception_message=None,
                                     kill_signal=signal.SIGKILL):
        self.proc.run_as_root = True
        if exception_message:
            exc = RuntimeError(exception_message)
        else:
            exc = None
        with mock.patch.object(utils, 'kill_process',
                               side_effect=exc) as mock_kill_process:
            actual = self.proc._kill_process(pid, kill_signal)

        self.assertEqual(expected, actual)
        mock_kill_process.assert_called_with(pid,
                                             kill_signal,
                                             self.proc.run_as_root)

    def test__kill_process_and_wait_returns_true_for_valid_pid(self):
        self._test__kill_process_and_wait('1', True)

    def test__kill_process_and_wait_returns_false_for_execute_exception(self):
        self._test__kill_process_and_wait('1', False, 'Invalid')

    def test_kill_process_and_wait_with_different_signal(self):
        self._test__kill_process_and_wait(
            '1', True, kill_signal=signal.SIGTERM)

    def test__kill_process_timeout_reached(self):
        self.proc.run_as_root = True
        kill_timeout = 5
        pid = '1'
        with mock.patch.object(utils, 'kill_process') as mock_kill_process, \
                mock.patch.object(self.proc, '_process') as process_mock:
            process_mock.wait.side_effect = subprocess.TimeoutExpired(
                self.proc.cmd, kill_timeout)
            self.assertTrue(
                self.proc._kill_process_and_wait(
                    pid, signal.SIGTERM, kill_timeout))

        process_mock.wait.assert_called_once_with(kill_timeout)
        mock_kill_process.assert_has_calls([
            mock.call(pid, signal.SIGTERM, self.proc.run_as_root),
            mock.call(pid, signal.SIGKILL, self.proc.run_as_root)])

    def test_stop_calls_kill_with_provided_signal_number(self):
        self.proc._is_running = True
        with mock.patch.object(self.proc, '_kill') as mock_kill:
            self.proc.stop(kill_signal=signal.SIGTERM)
        mock_kill.assert_called_once_with(signal.SIGTERM, None)

    def test_stop_raises_exception_if_already_started(self):
        with testtools.ExpectedException(async_process.AsyncProcessException):
            self.proc.stop()

    def test_cmd(self):
        for expected, cmd in (('ls -l file', ['ls', '-l', 'file']),
                              ('fake', ['fake'])):
            proc = async_process.AsyncProcess(cmd)
            self.assertEqual(expected, proc.cmd)


class TestAsyncProcessLogging(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.log_mock = mock.patch.object(async_process, 'LOG').start()

    def _test__read_stdout_logging(self, enable):
        proc = async_process.AsyncProcess(['fakecmd'], log_output=enable)
        with mock.patch.object(proc, '_read', return_value='fakedata'),\
                mock.patch.object(proc, '_process'):
            proc._read_stdout()
        self.assertEqual(enable, self.log_mock.debug.called)

    def _test__read_stderr_logging(self, enable):
        proc = async_process.AsyncProcess(['fake'], log_output=enable)
        with mock.patch.object(proc, '_read', return_value='fakedata'),\
                mock.patch.object(proc, '_process'):
            proc._read_stderr()
        self.assertEqual(enable, self.log_mock.error.called)

    def test__read_stdout_logging_enabled(self):
        self._test__read_stdout_logging(enable=True)

    def test__read_stdout_logging_disabled(self):
        self._test__read_stdout_logging(enable=False)

    def test__read_stderr_logging_enabled(self):
        self._test__read_stderr_logging(enable=True)

    def test__read_stderr_logging_disabled(self):
        self._test__read_stderr_logging(enable=False)


class TestAsyncProcessDieOnError(base.BaseTestCase):

    def test__read_stderr_returns_none_on_error(self):
        proc = async_process.AsyncProcess(['fakecmd'], die_on_error=True)
        with mock.patch.object(proc, '_read', return_value='fakedata'),\
                mock.patch.object(proc, '_process'):
            self.assertIsNone(proc._read_stderr())


class TestFailingAsyncProcess(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        path = self.get_temp_file_path('async.tmp', self.get_new_temp_dir())
        self.process = async_process.AsyncProcess([sys.executable,
                                                   failing_process.__file__,
                                                   path],
                                                  respawn_interval=0)

    def test_failing_async_process_handle_error_once(self):
        with mock.patch.object(self.process, '_handle_process_error')\
                as handle_error_mock:
            self.process.start()
            self.process._process.wait()
            # Wait for the monitor process to complete
            for thread in self.process._watchers:
                thread.join()
            self.assertEqual(1, handle_error_mock.call_count)
