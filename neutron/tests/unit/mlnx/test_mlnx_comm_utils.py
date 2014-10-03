# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo.config import cfg

from neutron.plugins.mlnx.common import comm_utils
from neutron.plugins.mlnx.common import config  # noqa
from neutron.plugins.mlnx.common import exceptions
from neutron.tests import base


class WrongException(Exception):
        pass


class TestRetryDecorator(base.BaseTestCase):
    def setUp(self):
        super(TestRetryDecorator, self).setUp()
        self.sleep_fn_p = mock.patch("time.sleep")
        self.sleep_fn = self.sleep_fn_p.start()

    def test_no_retry_required(self):
        self.counter = 0

        @comm_utils.RetryDecorator(exceptions.RequestTimeout, interval=2,
                                   retries=3, backoff_rate=2)
        def succeeds():
            self.counter += 1
            return 'success'

        ret = succeeds()
        self.assertFalse(self.sleep_fn.called)
        self.assertEqual(ret, 'success')
        self.assertEqual(self.counter, 1)

    def test_retry_zero_times(self):
        self.counter = 0
        interval = 2
        backoff_rate = 2
        retries = 0

        @comm_utils.RetryDecorator(exceptions.RequestTimeout, interval,
                                   retries, backoff_rate)
        def always_fails():
            self.counter += 1
            raise exceptions.RequestTimeout()

        self.assertRaises(exceptions.RequestTimeout, always_fails)
        self.assertEqual(self.counter, 1)
        self.assertFalse(self.sleep_fn.called)

    def test_retries_once(self):
        self.counter = 0
        interval = 2
        backoff_rate = 2
        retries = 3

        @comm_utils.RetryDecorator(exceptions.RequestTimeout, interval,
                                   retries, backoff_rate)
        def fails_once():
            self.counter += 1
            if self.counter < 2:
                raise exceptions.RequestTimeout()
            else:
                return 'success'

        ret = fails_once()
        self.assertEqual(ret, 'success')
        self.assertEqual(self.counter, 2)
        self.assertEqual(self.sleep_fn.call_count, 1)
        self.sleep_fn.assert_called_with(interval)

    def test_limit_is_reached(self):
        self.counter = 0
        retries = 3
        interval = 2
        backoff_rate = 4

        @comm_utils.RetryDecorator(exceptions.RequestTimeout, interval,
                                   retries, backoff_rate)
        def always_fails():
            self.counter += 1
            raise exceptions.RequestTimeout()

        self.assertRaises(exceptions.RequestTimeout, always_fails)
        self.assertEqual(self.counter, retries + 1)
        self.assertEqual(self.sleep_fn.call_count, retries)

        expected_sleep_fn_arg = []
        for i in range(retries):
            expected_sleep_fn_arg.append(interval)
            interval *= backoff_rate

        self.sleep_fn.assert_has_calls(map(mock.call, expected_sleep_fn_arg))

    def test_limit_is_reached_with_conf(self):
        self.counter = 0

        @comm_utils.RetryDecorator(exceptions.RequestTimeout)
        def always_fails():
            self.counter += 1
            raise exceptions.RequestTimeout()

        retry = cfg.CONF.ESWITCH.retries
        interval = cfg.CONF.ESWITCH.request_timeout / 1000
        delay_rate = cfg.CONF.ESWITCH.backoff_rate

        expected_sleep_fn_arg = []
        for i in range(retry):
            expected_sleep_fn_arg.append(interval)
            interval *= delay_rate

        self.assertRaises(exceptions.RequestTimeout, always_fails)
        self.assertEqual(self.counter, retry + 1)
        self.assertEqual(self.sleep_fn.call_count, retry)
        self.sleep_fn.assert_has_calls(map(mock.call, expected_sleep_fn_arg))

    def test_wrong_exception_no_retry(self):

        @comm_utils.RetryDecorator(exceptions.RequestTimeout)
        def raise_unexpected_error():
            raise WrongException("wrong exception")

        self.assertRaises(WrongException, raise_unexpected_error)
        self.assertFalse(self.sleep_fn.called)
