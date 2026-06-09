# Copyright 2026 Red Hat, Inc.
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

import errno
from unittest import mock

from pyroute2.iproute.ipmock import MockLink
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg

from neutron.agent.linux import nl_constants as nl_const
from neutron.agent.linux import nl_dispatcher
from neutron.tests import base


def _make_nlmsg(ifname, event, kind=None):
    data = MockLink(index=1, ifname=ifname, kind=kind).export()
    msg = ifinfmsg()
    msg.load(data)
    msg.encode()
    decoded = ifinfmsg(msg.data)
    decoded.decode()
    decoded['event'] = event
    return decoded


class TestNetlinkDispatcher(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_iproute = mock.patch.object(
            nl_dispatcher, 'iproute').start()
        self.mock_ipr = self.mock_iproute.IPRoute.return_value
        self.mock_ipr.dump.return_value = []
        self.mock_time = mock.patch.object(
            nl_dispatcher, 'time').start()
        self.dispatcher = nl_dispatcher.NetlinkDispatcher(rtnl.RTMGRP_LINK)

    def test_register_handler(self):
        handler1 = mock.Mock()
        handler2 = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler1)
        self.dispatcher.register_handler(nl_const.RTM_DELLINK, handler2)
        self.assertIn(nl_const.RTM_NEWLINK, self.dispatcher._handlers)
        self.assertIn(nl_const.RTM_DELLINK, self.dispatcher._handlers)
        self.assertIs(
            self.dispatcher._handlers[nl_const.RTM_NEWLINK], handler1)
        self.assertIs(
            self.dispatcher._handlers[nl_const.RTM_DELLINK], handler2)

    def test_dispatch_routes_to_matching_handler(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msg = _make_nlmsg('eth0', nl_const.RTM_NEWLINK)
        self.dispatcher._dispatch(msg)
        handler.assert_called_once_with(msg)

    def test_dispatch_ignores_unregistered_event(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msg = _make_nlmsg('eth0', 'RTM_NEWADDR')
        self.dispatcher._dispatch(msg)
        handler.assert_not_called()

    def test_replay_dispatches_dump_messages(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msgs = [_make_nlmsg('eth0', nl_const.RTM_NEWLINK),
                _make_nlmsg('eth1', nl_const.RTM_NEWLINK)]
        self.mock_ipr.dump.return_value = msgs
        self.dispatcher._replay(self.mock_ipr)
        self.assertEqual(2, handler.call_count)

    @mock.patch('threading.Thread')
    def test_start_spawns_daemon_thread(self, mock_thread_cls):
        mock_thread = mock_thread_cls.return_value
        self.dispatcher.start()
        mock_thread_cls.assert_called_once_with(
            target=self.dispatcher._dispatcher_loop,
            name='netlink-dispatcher',
            daemon=True)
        mock_thread.start.assert_called_once()

    def test_replay_calls_start_before_dispatch_and_end_after(self):
        tracker = mock.Mock()
        self.dispatcher.register_handler(
            nl_const.RTM_NEWLINK, tracker.dispatch)
        self.dispatcher.register_replay_callbacks(
            on_start=tracker.start, on_end=tracker.end)
        msg = _make_nlmsg('eth0', nl_const.RTM_NEWLINK)
        self.mock_ipr.dump.return_value = [msg]
        self.dispatcher._replay(self.mock_ipr)
        tracker.assert_has_calls(
            [mock.call.start(), mock.call.dispatch(msg), mock.call.end()])

    def test_replay_callbacks_called_once_per_replay(self):
        tracker = mock.Mock()
        self.dispatcher.register_handler(
            nl_const.RTM_NEWLINK, tracker.dispatch)
        self.dispatcher.register_replay_callbacks(
            on_start=tracker.start, on_end=tracker.end)
        msgs = [_make_nlmsg('eth0', nl_const.RTM_NEWLINK),
                _make_nlmsg('eth1', nl_const.RTM_NEWLINK)]
        self.mock_ipr.dump.return_value = msgs
        self.dispatcher._replay(self.mock_ipr)
        tracker.start.assert_called_once()
        tracker.end.assert_called_once()
        self.assertEqual(2, tracker.dispatch.call_count)


class TestNetlinkDispatcherLoop(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_iproute = mock.patch.object(
            nl_dispatcher, 'iproute').start()
        self.mock_ipr = self.mock_iproute.IPRoute.return_value
        self.mock_ipr.dump.return_value = []
        self.mock_time = mock.patch.object(
            nl_dispatcher, 'time').start()
        self.mock_exit = mock.patch.object(
            nl_dispatcher.os, '_exit', side_effect=SystemExit).start()
        self.dispatcher = nl_dispatcher.NetlinkDispatcher(rtnl.RTMGRP_LINK)

    def _run_loop(self):
        # Gracefully handle the process termination when breaking out of the
        # loop to continue test, since the test uses RuntimeError to break
        # out of the dispatcher loop and the RuntimeError in turn causes the
        # dispatcher thread to terminate
        self.assertRaises(SystemExit, self.dispatcher._dispatcher_loop)

    def test_loop_dispatches_messages(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msg = _make_nlmsg('eth0', nl_const.RTM_NEWLINK)
        self.mock_ipr.get.side_effect = [[msg], RuntimeError]
        self._run_loop()
        handler.assert_called_once_with(msg)

    def test_loop_opens_sock_and_replays_on_start(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msg = _make_nlmsg('eth0', nl_const.RTM_NEWLINK)
        self.mock_ipr.dump.return_value = [msg]
        self.mock_ipr.get.side_effect = RuntimeError
        self._run_loop()
        self.mock_ipr.bind.assert_called_once()
        self.mock_ipr.dump.assert_called_once()
        handler.assert_called_once_with(msg)

    def test_enobufs_triggers_replay(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msg = _make_nlmsg('eth0', nl_const.RTM_NEWLINK)
        self.mock_ipr.dump.return_value = [msg]
        self.mock_ipr.get.side_effect = [
            OSError(errno.ENOBUFS, 'No buffer space'),
            RuntimeError,
        ]
        self._run_loop()
        self.assertEqual(2, self.mock_ipr.dump.call_count)
        self.assertEqual(2, handler.call_count)

    def test_socket_error_reopens_with_backoff(self):
        self.mock_ipr.get.side_effect = [
            OSError(errno.EBADF, 'Bad file descriptor'),
            RuntimeError,
        ]
        self._run_loop()
        self.mock_time.sleep.assert_called_once_with(
            self.dispatcher.RETRY_BACKOFF)
        self.assertEqual(
            2, self.mock_iproute.IPRoute.call_count)

    def test_socket_error_retries_reset_on_success(self):
        handler = mock.Mock()
        self.dispatcher.register_handler(nl_const.RTM_NEWLINK, handler)
        msg = _make_nlmsg('eth0', nl_const.RTM_NEWLINK)
        self.mock_ipr.get.side_effect = [
            OSError(errno.EBADF, 'Bad file descriptor'),
            [msg],
            RuntimeError,
        ]
        self._run_loop()
        handler.assert_called_once_with(msg)

    def test_unexpected_exception_exits_agent(self):
        self.mock_ipr.get.side_effect = RuntimeError('unexpected')
        self._run_loop()
        self.mock_ipr.close.assert_called()
        self.mock_exit.assert_called_once_with(1)
