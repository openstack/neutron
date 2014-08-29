# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

import mock
import requests

from oslo.config import cfg

from neutron.common import config as neutron_config
from neutron.plugins.ml2 import config as ml2_config
from neutron.tests import base


OK = requests.codes.ok

APIC_HOSTS = ['fake.controller.local']
APIC_PORT = 7580
APIC_USR = 'notadmin'
APIC_PWD = 'topsecret'

APIC_TENANT = 'citizen14'
APIC_NETWORK = 'network99'
APIC_NETNAME = 'net99name'
APIC_SUBNET = '10.3.2.1/24'
APIC_L3CTX = 'layer3context'
APIC_AP = 'appProfile001'
APIC_EPG = 'endPointGroup001'

APIC_CONTRACT = 'signedContract'
APIC_SUBJECT = 'testSubject'
APIC_FILTER = 'carbonFilter'
APIC_ENTRY = 'forcedEntry'

APIC_VMMP = 'OpenStack'
APIC_DOMAIN = 'cumuloNimbus'
APIC_PDOM = 'rainStorm'

APIC_NODE_PROF = 'red'
APIC_LEAF = 'green'
APIC_LEAF_TYPE = 'range'
APIC_NODE_BLK = 'blue'
APIC_PORT_PROF = 'yellow'
APIC_PORT_SEL = 'front'
APIC_PORT_TYPE = 'range'
APIC_PORT_BLK1 = 'block01'
APIC_PORT_BLK2 = 'block02'
APIC_ACC_PORT_GRP = 'alpha'
APIC_FUNC_PROF = 'beta'
APIC_ATT_ENT_PROF = 'delta'
APIC_VLAN_NAME = 'gamma'
APIC_VLAN_MODE = 'dynamic'
APIC_VLANID_FROM = 2900
APIC_VLANID_TO = 2999
APIC_VLAN_FROM = 'vlan-%d' % APIC_VLANID_FROM
APIC_VLAN_TO = 'vlan-%d' % APIC_VLANID_TO


class ControllerMixin(object):

    """Mock the controller for APIC driver and service unit tests."""

    def __init__(self):
        self.response = None

    def set_up_mocks(self):
        # The mocked responses from the server are lists used by
        # mock.side_effect, which means each call to post or get will
        # return the next item in the list. This allows the test cases
        # to stage a sequence of responses to method(s) under test.
        self.response = {'post': [], 'get': []}
        self.reset_reponses()

    def reset_reponses(self, req=None):
        # Clear all staged responses.
        reqs = req and [req] or ['post', 'get']  # Both if none specified.
        for req in reqs:
            del self.response[req][:]
            self.restart_responses(req)

    def restart_responses(self, req):
        responses = mock.MagicMock(side_effect=self.response[req])
        if req == 'post':
            requests.Session.post = responses
        elif req == 'get':
            requests.Session.get = responses

    def mock_response_for_post(self, mo, **attrs):
        attrs['debug_mo'] = mo  # useful for debugging
        self._stage_mocked_response('post', OK, mo, **attrs)

    def _stage_mocked_response(self, req, mock_status, mo, **attrs):
        response = mock.MagicMock()
        response.status_code = mock_status
        mo_attrs = attrs and [{mo: {'attributes': attrs}}] or []
        response.json.return_value = {'imdata': mo_attrs}
        self.response[req].append(response)

    def mock_apic_manager_login_responses(self, timeout=300):
        # APIC Manager tests are based on authenticated session
        self.mock_response_for_post('aaaLogin', userName=APIC_USR,
                                    token='ok', refreshTimeoutSeconds=timeout)


class ConfigMixin(object):

    """Mock the config for APIC driver and service unit tests."""

    def __init__(self):
        self.mocked_parser = None

    def set_up_mocks(self):
        # Mock the configuration file
        args = ['--config-file', base.etcdir('neutron.conf.test')]
        neutron_config.init(args=args)

        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['apic'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
                ml2_config.cfg.CONF.set_override(opt, val, 'ml2')

        # Configure the Cisco APIC mechanism driver
        apic_test_config = {
            'apic_hosts': APIC_HOSTS,
            'apic_username': APIC_USR,
            'apic_password': APIC_PWD,
            'apic_vmm_domain': APIC_DOMAIN,
            'apic_vlan_ns_name': APIC_VLAN_NAME,
            'apic_vlan_range': '%d:%d' % (APIC_VLANID_FROM, APIC_VLANID_TO),
            'apic_node_profile': APIC_NODE_PROF,
            'apic_entity_profile': APIC_ATT_ENT_PROF,
            'apic_function_profile': APIC_FUNC_PROF,
        }
        for opt, val in apic_test_config.items():
            cfg.CONF.set_override(opt, val, 'ml2_cisco_apic')

        apic_switch_cfg = {
            'apic_switch:east01': {'ubuntu1,ubuntu2': ['3/11']},
            'apic_switch:east02': {'rhel01,rhel02': ['4/21'],
                                   'rhel03': ['4/22']},
        }
        self.mocked_parser = mock.patch.object(cfg,
                                               'MultiConfigParser').start()
        self.mocked_parser.return_value.read.return_value = [apic_switch_cfg]
        self.mocked_parser.return_value.parsed = [apic_switch_cfg]
