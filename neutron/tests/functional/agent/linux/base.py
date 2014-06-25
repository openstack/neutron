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

from neutron.agent.linux import ovs_lib
from neutron.agent.linux import utils
from neutron.common import constants as n_const
from neutron.tests import base


BR_PREFIX = 'test-br'


class BaseLinuxTestCase(base.BaseTestCase):
    def setUp(self, root_helper='sudo'):
        super(BaseLinuxTestCase, self).setUp()

        self.root_helper = root_helper

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

    def create_resource(self, name_prefix, creation_func, *args, **kwargs):
        """Create a new resource that does not already exist.

        :param name_prefix: The prefix for a randomly generated name
        :param creation_func: A function taking the name of the resource
               to be created as it's first argument.  An error is assumed
               to indicate a name collision.
        :param *args *kwargs: These will be passed to the create function.
        """
        while True:
            name = self.get_rand_name(n_const.DEV_NAME_MAX_LEN, name_prefix)
            try:
                return creation_func(name, *args, **kwargs)
            except RuntimeError:
                continue


class BaseOVSLinuxTestCase(BaseLinuxTestCase):
    def setUp(self, root_helper='sudo'):
        super(BaseOVSLinuxTestCase, self).setUp(root_helper)
        self.ovs = ovs_lib.BaseOVS(self.root_helper)

    def create_ovs_bridge(self, br_prefix=BR_PREFIX):
        br = self.create_resource(br_prefix, self.ovs.add_bridge)
        self.addCleanup(br.destroy)
        return br
