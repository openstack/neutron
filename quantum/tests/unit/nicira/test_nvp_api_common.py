# Copyright (C) 2009-2011 Nicira Networks, Inc. All Rights Reserved.
#
# This software is provided only under the terms and conditions of a written
# license agreement with Nicira. If no such agreement applies to you, you are
# not authorized to use this software. Contact Nicira to obtain an appropriate
# license: www.nicira.com.

# System
import httplib
import unittest

# Third party
# Local
import quantum.plugins.nicira.nicira_nvp_plugin.api_client.common as naco


class NvpApiCommonTest(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_conn_str(self):
        conn = httplib.HTTPSConnection('localhost', 4242, timeout=0)
        self.assertTrue(
            naco._conn_str(conn) == 'https://localhost:4242')

        conn = httplib.HTTPConnection('localhost', 4242, timeout=0)
        self.assertTrue(
            naco._conn_str(conn) == 'http://localhost:4242')

        self.assertRaises(TypeError, naco._conn_str,
                          ('not an httplib.HTTPSConnection'))
