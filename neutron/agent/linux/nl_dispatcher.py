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

import contextlib
import errno
import os
import threading
import time

from oslo_log import log
from pyroute2 import iproute

LOG = log.getLogger(__name__)


class NetlinkDispatcher:
    """Monitor netlink for multicast group events and dispatch the messages.

    Runs a daemon thread that binds a netlink socket to the specified
    multicast groups and dispatches messages to registered handlers.
    """

    RETRY_BACKOFF = 10   # Back off for 10 seconds before reopening socket

    def __init__(self, groups):
        self._thread = None
        self._handlers = {}
        self._groups = groups
        self._replay_start_callbacks = []
        self._replay_end_callbacks = []

    def register_handler(self, event_type, handler):
        """Register a handler for a specific netlink message type.

        :param event_type: message type string (e.g. 'RTM_NEWLINK')
        :param handler: callable(msg) invoked for each matching message
        """
        self._handlers[event_type] = handler

    def register_replay_callbacks(self, on_start=None, on_end=None):
        """Register callbacks invoked before and after each replay.

        :param on_start: callable() invoked before replay dump begins
        :param on_end: callable() invoked after replay dump completes
        """
        if on_start:
            self._replay_start_callbacks.append(on_start)
        if on_end:
            self._replay_end_callbacks.append(on_end)

    def start(self):
        self._thread = threading.Thread(
            target=self._dispatcher_loop,
            name='netlink-dispatcher',
            daemon=True)
        self._thread.start()
        LOG.info("NetlinkDispatcher started")

    @contextlib.contextmanager
    def _sock(self):
        ipr = iproute.IPRoute()
        ipr.bind(self._groups)
        try:
            yield ipr
        finally:
            ipr.close()

    def _replay(self, ipr):
        """Dump current state and replay it through all handlers."""
        for cb in self._replay_start_callbacks:
            cb()
        for msg in ipr.dump(groups=self._groups):
            self._dispatch(msg)
        for cb in self._replay_end_callbacks:
            cb()

    def _dispatch(self, msg):
        """Dispatch message to the handler registered for its type."""
        try:
            handler = self._handlers[msg.get('event')]
        except KeyError:
            LOG.debug("No handler for event %s", msg.get('event'))
            return
        handler(msg)

    def _dispatcher_loop(self):
        retries = 0
        while True:
            try:
                with self._sock() as ipr:
                    self._replay(ipr)
                    while True:
                        try:
                            for msg in ipr.get():
                                self._dispatch(msg)
                                retries = 0
                        except OSError as e:
                            if e.errno == errno.ENOBUFS:
                                LOG.warning("Netlink receive buffer overrun, "
                                            "replaying handlers")
                                self._replay(ipr)
                            else:
                                retries += 1
                                LOG.error("Netlink socket error: %s, "
                                          "reopening in %d seconds "
                                          "(retry %d)", e,
                                          self.RETRY_BACKOFF, retries)
                                time.sleep(self.RETRY_BACKOFF)
                                break
            except Exception:
                LOG.exception("NetlinkDispatcher crashed")
                os._exit(1)
