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
from oslo_config import cfg
from oslo_config import fixture as config_fixture

from neutron.common import cache_utils as cache
from neutron.tests import base


class CacheConfFixture(config_fixture.Config):
    def setUp(self):
        super(CacheConfFixture, self).setUp()
        cache.register_oslo_configs(self.conf)
        self.config(enabled=True, group='cache')


class TestOsloCache(base.BaseTestCase):
    def setUp(self):
        super(TestOsloCache, self).setUp()
        self.memory_conf = cfg.ConfigOpts()
        memory_conf_fixture = CacheConfFixture(self.memory_conf)
        self.useFixture(memory_conf_fixture)

        self.dict_conf = cfg.ConfigOpts()
        dict_conf_fixture = CacheConfFixture(self.dict_conf)
        self.useFixture(dict_conf_fixture)
        dict_conf_fixture.config(expiration_time=60,
                                 backend='oslo_cache.dict', group='cache')

        self.null_cache_conf = cfg.ConfigOpts()
        null_conf_fixture = CacheConfFixture(self.null_cache_conf)
        self.useFixture(null_conf_fixture)
        null_conf_fixture.config(expiration_time=600,
                                 backend='dogpile.cache.null', group='cache')

    def _test_get_cache_region_helper(self, conf):
        region = cache._get_cache_region(conf)
        self.assertIsNotNone(region)

    def test_get_cache_region(self):
        self._test_get_cache_region_helper(self.dict_conf)
        self._test_get_cache_region_helper(self.null_cache_conf)

    @mock.patch('neutron.common.cache_utils._get_cache_region')
    def test_get_cache(self, mock_get_cache_region):
        self.assertIsNotNone(cache.get_cache(self.memory_conf))
        self.assertIsNotNone(cache.get_cache(self.dict_conf))
        self.assertIsNotNone(cache.get_cache(self.null_cache_conf))
        mock_get_cache_region.assert_has_calls(
            [mock.call(self.dict_conf),
             mock.call(self.null_cache_conf)]
        )


class _CachingDecorator(object):
    def __init__(self):
        self.func_retval = 'bar'
        self._cache = mock.Mock()

    @cache.cache_method_results
    def func(self, *args, **kwargs):
        return self.func_retval


class TestCachingDecorator(base.BaseTestCase):
    def setUp(self):
        super(TestCachingDecorator, self).setUp()
        self.decor = _CachingDecorator()
        self.func_name = '%(module)s._CachingDecorator.func' % {
            'module': self.__module__
        }
        self.not_cached = self.decor.func.func.__self__._not_cached

    def test_cache_miss(self):
        expected_key = (self.func_name, 1, 2, ('foo', 'bar'))
        args = (1, 2)
        kwargs = {'foo': 'bar'}
        self.decor._cache.get.return_value = self.not_cached
        retval = self.decor.func(*args, **kwargs)
        self.decor._cache.set.assert_called_once_with(
            str(expected_key), self.decor.func_retval)
        self.assertEqual(self.decor.func_retval, retval)

    def test_cache_hit(self):
        expected_key = (self.func_name, 1, 2, ('foo', 'bar'))
        args = (1, 2)
        kwargs = {'foo': 'bar'}
        retval = self.decor.func(*args, **kwargs)
        self.assertFalse(self.decor._cache.set.called)
        self.assertEqual(self.decor._cache.get.return_value, retval)
        self.decor._cache.get.assert_called_once_with(str(expected_key))

    def test_get_unhashable(self):
        expected_key = (self.func_name, [1], 2)
        self.decor._cache.get.side_effect = TypeError
        retval = self.decor.func([1], 2)
        self.assertFalse(self.decor._cache.set.called)
        self.assertEqual(self.decor.func_retval, retval)
        self.decor._cache.get.assert_called_once_with(str(expected_key))

    def test_missing_cache(self):
        delattr(self.decor, '_cache')
        self.assertRaises(NotImplementedError, self.decor.func, (1, 2))

    def test_no_cache(self):
        self.decor._cache = False
        retval = self.decor.func((1, 2))
        self.assertEqual(self.decor.func_retval, retval)
