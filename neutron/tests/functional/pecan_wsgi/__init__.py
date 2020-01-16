# Copyright (c) 2015 Mirantis, Inc.
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


import os
import unittest

from pecan import set_config
from pecan.testing import load_test_app


__all__ = ['FunctionalTest']


class FunctionalTest(unittest.TestCase):
    """Pecan wsgi functional test base class

    Used for functional tests where you need to test your
    literal application and its integration with the framework.
    """

    def setUp(self):
        self.app = load_test_app(os.path.join(
            os.path.dirname(__file__),
            'config.py'
        ))
        self.addCleanup(set_config, {}, overwrite=True)
