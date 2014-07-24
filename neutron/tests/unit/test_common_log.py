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


class TargetKlass(object):

    @call_log.log
    def test_method(self, arg1, arg2, *args, **kwargs):
        pass


class TestCallLog(base.BaseTestCase):
    def setUp(self):
        super(TestCallLog, self).setUp()
        self.klass = TargetKlass()
        logger = self.klass.test_method.im_func.func_closure[0].cell_contents
        self.log_debug = mock.patch.object(logger, 'debug').start()

    def _test_call_log(self, *args, **kwargs):
        expected_format = ('%(class_name)s method %(method_name)s '
                           'called with arguments %(args)s %(kwargs)s')
        expected_data = {'class_name': '%s.%s' % (
                         __name__,
                         self.klass.__class__.__name__),
                         'method_name': 'test_method',
                         'args': args,
                         'kwargs': kwargs}
        self.klass.test_method(*args, **kwargs)
        self.log_debug.assert_called_once_with(expected_format, expected_data)

    def test_call_log_all_args(self):
        self._test_call_log(10, 20)

    def test_call_log_all_kwargs(self):
        self._test_call_log(arg1=10, arg2=20)

    def test_call_log_known_args_unknown_args_kwargs(self):
        self._test_call_log(10, 20, 30, arg4=40)

    def test_call_log_known_args_kwargs_unknown_kwargs(self):
        self._test_call_log(10, arg2=20, arg3=30, arg4=40)
