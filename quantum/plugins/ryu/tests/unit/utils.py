# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import ConfigParser
import imp
import os
import tempfile
from StringIO import StringIO

import mock

from quantum.plugins.ryu.tests.unit import fake_rest_nw_id
from quantum.plugins.ryu.tests.unit import fake_ryu_client

FAKE_CONTROLLER_ADDR = '127.0.0.1:6633'
FAKE_REST_ADDR = '127.0.0.1:8080'
FAKE_RYU_INI_TEMPLATE = """
[DATABASE]
sql_connection = sqlite:///:memory:

[OVS]
integration-bridge = br-int
openflow-controller = %s
openflow-rest-api = %s
""" % (FAKE_CONTROLLER_ADDR, FAKE_REST_ADDR)


def create_fake_ryu_ini():
    fd, file_name = tempfile.mkstemp(suffix='.ini')
    tmp_file = os.fdopen(fd, 'w')
    tmp_file.write(FAKE_RYU_INI_TEMPLATE)
    tmp_file.close()
    return file_name


def get_config():
    config = ConfigParser.ConfigParser()
    buf_file = StringIO(FAKE_RYU_INI_TEMPLATE)
    config.readfp(buf_file)
    buf_file.close()
    return config


def patch_fake_ryu_client():
    ryu_mod = imp.new_module('ryu')
    ryu_app_mod = imp.new_module('ryu.app')
    ryu_mod.app = ryu_app_mod
    ryu_app_mod.client = fake_ryu_client
    ryu_app_mod.rest_nw_id = fake_rest_nw_id
    return mock.patch.dict('sys.modules',
                           {'ryu': ryu_mod,
                            'ryu.app': ryu_app_mod,
                            'ryu.app.client': fake_ryu_client,
                            'ryu.app.rest_nw_id': fake_rest_nw_id})


class Net(object):
    def __init__(self, uuid):
        self.uuid = uuid
