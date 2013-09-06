# Copyright (c) 2013 OpenStack Foundation.
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

import mock

from neutron.common import log as call_log
from neutron.tests import base


MODULE_NAME = 'neutron.tests.unit.test_common_log'


class TargetKlass(object):

    @call_log.log
    def test_method(self, arg1, arg2, *args, **kwargs):
        pass


class TestCallLog(base.BaseTestCase):
    def setUp(self):
        super(TestCallLog, self).setUp()
        self.klass = TargetKlass()
        self.expected_format = ('%(class_name)s method %(method_name)s '
                                'called with arguments %(args)s %(kwargs)s')
        self.expected_data = {'class_name': MODULE_NAME + '.TargetKlass',
                              'method_name': 'test_method',
                              'args': (),
                              'kwargs': {}}

    def test_call_log_all_args(self):
        self.expected_data['args'] = (10, 20)
        with mock.patch.object(call_log.LOG, 'debug') as log_debug:
            self.klass.test_method(10, 20)
            log_debug.assert_called_once_with(self.expected_format,
                                              self.expected_data)

    def test_call_log_all_kwargs(self):
        self.expected_data['kwargs'] = {'arg1': 10, 'arg2': 20}
        with mock.patch.object(call_log.LOG, 'debug') as log_debug:
            self.klass.test_method(arg1=10, arg2=20)
            log_debug.assert_called_once_with(self.expected_format,
                                              self.expected_data)

    def test_call_log_known_args_unknown_args_kwargs(self):
        self.expected_data['args'] = (10, 20, 30)
        self.expected_data['kwargs'] = {'arg4': 40}
        with mock.patch.object(call_log.LOG, 'debug') as log_debug:
            self.klass.test_method(10, 20, 30, arg4=40)
            log_debug.assert_called_once_with(self.expected_format,
                                              self.expected_data)

    def test_call_log_known_args_kwargs_unknown_kwargs(self):
        self.expected_data['args'] = (10,)
        self.expected_data['kwargs'] = {'arg2': 20, 'arg3': 30, 'arg4': 40}
        with mock.patch.object(call_log.LOG, 'debug') as log_debug:
            self.klass.test_method(10, arg2=20, arg3=30, arg4=40)
            log_debug.assert_called_once_with(self.expected_format,
                                              self.expected_data)
