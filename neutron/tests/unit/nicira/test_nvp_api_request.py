# Copyright (C) 2009-2011 Nicira Networks, Inc. All Rights Reserved.
#
# This software is provided only under the terms and conditions of a written
# license agreement with Nicira. If no such agreement applies to you, you are
# not authorized to use this software. Contact Nicira to obtain an appropriate
# license: www.nicira.com.

import eventlet
eventlet.monkey_patch()
import logging
import urllib2

from neutron.tests import base

logging.basicConfig(level=logging.DEBUG)
lg = logging.getLogger("test_nvp_api_request")

REQUEST_TIMEOUT = 1


def fetch(url):
    return urllib2.urlopen(url).read()


class NvpApiRequestTest(base.BaseTestCase):

    pass
