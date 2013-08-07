# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira, Inc.
# All Rights Reserved
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
