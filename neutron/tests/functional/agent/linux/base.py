# Copyright 2014 Cisco Systems, Inc.
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
import random

from neutron.agent.linux import utils
from neutron.plugins.common import constants as q_const
from neutron.tests import base


class BaseLinuxTestCase(base.BaseTestCase):

    def check_command(self, cmd, error_text, skip_msg):
        try:
            utils.execute(cmd)
        except RuntimeError as e:
            if error_text in str(e):
                self.skipTest(skip_msg)
            raise

    def check_sudo_enabled(self):
        if os.environ.get('OS_SUDO_TESTING') not in base.TRUE_STRING:
            self.skipTest('testing with sudo is not enabled')

    def get_rand_name(self, max_length, prefix='test'):
        name = prefix + str(random.randint(1, 0x7fffffff))
        return name[:max_length]

    def create_ovs_resource(self, name_prefix, creation_func):
        """Create a new ovs resource that does not already exist.

        :param name_prefix: The prefix for a randomly generated name
        :param creation_func: A function taking the name of the resource
               to be created.  An error is assumed to indicate a name
               collision.
        """
        while True:
            name = self.get_rand_name(q_const.MAX_DEV_NAME_LEN, name_prefix)
            try:
                return creation_func(name)
            except RuntimeError:
                continue
