# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
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
import socket

import unittest2 as unittest

from quantum import wsgi


class TestWSGIServer(unittest.TestCase):
    """WSGI server tests."""

    def test_start_random_port(self):
        server = wsgi.Server("test_random_port")
        server.start(None, 0, host="127.0.0.1")
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()

    def test_start_random_port_with_ipv6(self):
        server = wsgi.Server("test_random_port")
        server.start(None, 0, host="::1")
        self.assertEqual("::1", server.host)
        self.assertNotEqual(0, server.port)
        server.stop()
        server.wait()


class TestWSGIServer2(unittest.TestCase):
    def setUp(self):
        self.eventlet_p = mock.patch.object(wsgi, 'eventlet')
        self.eventlet = self.eventlet_p.start()
        self.server = wsgi.Server("test_app")

    def tearDown(self):
        self.eventlet_p.stop()

    def test_ipv6_with_link_local_start(self):
        mock_app = mock.Mock()
        with mock.patch.object(self.server, 'pool') as pool:
            self.server.start(mock_app,
                              0,
                              host="fe80::204:acff:fe96:da87%eth0")
            self.eventlet.assert_has_calls([
                mock.call.listen(('fe80::204:acff:fe96:da87%eth0', 0, 0, 2),
                                 backlog=128,
                                 family=10)
            ])
            pool.spawn.assert_has_calls([mock.call(
                self.server._run,
                mock_app,
                self.eventlet.listen.mock_calls[0].return_value)
            ])
