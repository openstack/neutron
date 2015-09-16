# Copyright (c) 2015 IBM Corp.
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

import hashlib
import mock


from neutron.plugins.common import utils
from neutron.tests import base


LONG_NAME1 = "A_REALLY_LONG_INTERFACE_NAME1"
LONG_NAME2 = "A_REALLY_LONG_INTERFACE_NAME2"
SHORT_NAME = "SHORT"

MOCKED_HASH = "mockedhash"


class MockSHA(object):
    def hexdigest(self):
        return MOCKED_HASH


class TestUtils(base.BaseTestCase):

    @mock.patch.object(hashlib, 'sha1', return_value=MockSHA())
    def test_get_interface_name(self, mock_sha1):
        prefix = "pre-"
        postfix = ".1111"

        if_default_long = utils.get_interface_name(LONG_NAME1)
        if_default_short = utils.get_interface_name(SHORT_NAME)

        if_prefix_long = utils.get_interface_name(LONG_NAME1, prefix=prefix)
        if_prefix_short = utils.get_interface_name(SHORT_NAME, prefix=prefix)

        if_postfix_long = utils.get_interface_name(LONG_NAME1, postfix=postfix)
        if_postfix_short = utils.get_interface_name(SHORT_NAME,
                                                    postfix=postfix)

        if_prefix_postfix_long = utils.get_interface_name(LONG_NAME1,
                                                          prefix=prefix,
                                                          postfix=postfix)
        if_prefix_postfix_short = utils.get_interface_name(SHORT_NAME,
                                                           prefix=prefix,
                                                           postfix=postfix)

        # Each combination is a tuple of the following values:
        # the calculated name, the expected name"
        combinations = [(if_default_long, "A_REALLY_mocked"),
                        (if_default_short, "SHORT"),
                        (if_prefix_long, "pre-A_REAmocked"),
                        (if_prefix_short, "pre-SHORT"),
                        (if_postfix_long, "A_REmocked.1111"),
                        (if_postfix_short, "SHORT.1111"),
                        (if_prefix_postfix_long, "pre-mocked.1111"),
                        (if_prefix_postfix_short, "pre-SHORT.1111")]

        for if_new_name, if_expected_new_name in combinations:
            self.assertEqual(if_new_name, if_expected_new_name)

    def test_get_interface_uniqueness(self):
        prefix = "prefix-"
        if_prefix1 = utils.get_interface_name(LONG_NAME1, prefix=prefix)
        if_prefix2 = utils.get_interface_name(LONG_NAME2, prefix=prefix)
        self.assertNotEqual(if_prefix1, if_prefix2)

    def test_get_interface_long_post_and_prefix(self):
        """Prefix and postfix alone overcome the max character limit."""

        long_prefix = "long_pre"
        long_postfix = "long_pos"
        much_too_long_prefix = "much_too_long_prefix"
        much_too_long_postfix = "much_too_long_postfix"

        self.assertEqual("long_preSHORT", utils.get_interface_name(SHORT_NAME,
                                                           prefix=long_prefix))
        self.assertEqual("SHORTlong_pos", utils.get_interface_name(SHORT_NAME,
                                                        postfix=long_postfix))
        self.assertRaises(ValueError, utils.get_interface_name, SHORT_NAME,
                          prefix=long_prefix, postfix=long_postfix)

        self.assertRaises(ValueError, utils.get_interface_name, SHORT_NAME,
                          prefix=much_too_long_prefix)
        self.assertRaises(ValueError, utils.get_interface_name, SHORT_NAME,
                          postfix=much_too_long_postfix)

    @mock.patch.object(hashlib, 'sha1', return_value=MockSHA())
    def test_get_interface_max_len(self, mock_sha1):
        self.assertTrue(len(utils.get_interface_name(LONG_NAME1)) == 15)
        self.assertTrue(len(utils.get_interface_name(LONG_NAME1, max_len=10))
                        == 10)
