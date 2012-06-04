# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright 2011 Red Hat, Inc.
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

import os
import tempfile
import unittest

from quantum.openstack.common.cfg import ConfigFileValueError
from quantum.plugins.openvswitch.common import config


class OvsConfigTestCase(unittest.TestCase):
    def test_tunnel(self):
        configs = """[DATABASE]
sql_connection = testlink
reconnect_interval=100
[OVS]
enable_tunneling = True
integration_bridge = mybrint
tunnel_bridge = mybrtun
local_ip = 10.0.0.3
[AGENT]
root_helper = mysudo
polling_interval=50
"""

        (fd, path) = tempfile.mkstemp(prefix='ovs_config', suffix='.ini')

        try:
            os.write(fd, configs)
            os.close(fd)

            conf = config.parse(path)
            self.assertTrue(conf.OVS.enable_tunneling)
            self.assertEqual('mybrint', conf.OVS.integration_bridge)
            self.assertEqual('mybrtun', conf.OVS.tunnel_bridge)
            self.assertEqual('testlink', conf.DATABASE.sql_connection)
            self.assertEqual(100, conf.DATABASE.reconnect_interval)
            self.assertEqual(50, conf.AGENT.polling_interval)
            self.assertEqual('mysudo', conf.AGENT.root_helper)
        finally:
            os.remove(path)

    def test_defaults(self):
        configs = """
"""

        (fd, path) = tempfile.mkstemp(prefix='ovs_config', suffix='.ini')

        try:
            os.write(fd, configs)
            os.close(fd)

            conf = config.parse(path)
            self.assertFalse(conf.OVS.enable_tunneling)
            self.assertEqual('br-int', conf.OVS.integration_bridge)
            self.assertEqual('br-tun', conf.OVS.tunnel_bridge)
            self.assertEqual('sqlite://', conf.DATABASE.sql_connection)
            self.assertEqual(2, conf.DATABASE.reconnect_interval)
            self.assertEqual(2, conf.AGENT.polling_interval)
            self.assertEqual('sudo', conf.AGENT.root_helper)
        finally:
            os.remove(path)

    def test_without_tunnel(self):
        configs = """
[OVS]
enable_tunneling = False
"""

        (fd, path) = tempfile.mkstemp(prefix='ovs_config', suffix='.ini')

        try:
            os.write(fd, configs)
            os.close(fd)

            conf = config.parse(path)
            self.assertFalse(conf.OVS.enable_tunneling)
        finally:
            os.remove(path)

    def test_invalid_values(self):
        configs = """
[OVS]
enable_tunneling = notbool
"""

        (fd, path) = tempfile.mkstemp(prefix='ovs_config', suffix='.ini')

        try:
            os.write(fd, configs)
            os.close(fd)
            conf = config.parse(path)
            exception_raised = False
            try:
                tunnel = conf.OVS.enable_tunneling
            except ConfigFileValueError:
                exception_raised = True
            self.assertTrue(exception_raised)
        finally:
            os.remove(path)
