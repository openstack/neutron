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

import functools

from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import reflection
from six.moves.urllib import parse

from neutron._i18n import _
from neutron.common import utils


cache_opts = [
    cfg.StrOpt('cache_url', default='',
               deprecated_for_removal=True,
               help=_('URL to connect to the cache back end. '
                      'This option is deprecated in the Newton release and '
                      'will be removed. Please add a [cache] group for '
                      'oslo.cache in your neutron.conf and add "enable" and '
                      '"backend" options in this section.')),
]

LOG = logging.getLogger(__name__)


def register_oslo_configs(conf):
    conf.register_opts(cache_opts)
    cache.configure(conf)


def get_cache(conf):
    """Used to get cache client"""
    # cache_url is still used, we just respect it. Memory backend is the only
    # backend supported before and default_ttl is the only options of Memory
    # backend. We use dict backend of oslo.cache for this.
    if conf.cache_url:
        return _get_cache_region_for_legacy(conf.cache_url)
    elif conf.cache.enabled:
        return _get_cache_region(conf)
    else:
        return False


def _get_cache_region(conf):
    region = cache.create_region()
    cache.configure_cache_region(conf, region)
    return region


def _get_cache_region_for_legacy(url):
    parsed = parse.urlparse(url)
    backend = parsed.scheme

    if backend == 'memory':
        backend = 'oslo_cache.dict'
        query = parsed.query
        # NOTE(fangzhen): The following NOTE and code is from legacy
        # oslo-incubator cache module. Previously reside in neutron at
        # neutron/openstack/common/cache/cache.py:78
        # NOTE(flaper87): We need the following hack
        # for python versions < 2.7.5. Previous versions
        # of python parsed query params just for 'known'
        # schemes. This was changed in this patch:
        # http://hg.python.org/cpython/rev/79e6ff3d9afd
        if not query and '?' in parsed.path:
            query = parsed.path.split('?', 1)[-1]
        parameters = parse.parse_qs(query)
        expiration_time = int(parameters.get('default_ttl', [0])[0])

        region = cache.create_region()
        region.configure(backend, expiration_time=expiration_time)
        return region
    else:
        raise RuntimeError(_('Old style configuration can use only memory '
                             '(dict) backend'))


class cache_method_results(object):
    """This decorator is intended for object methods only."""

    def __init__(self, func):
        self.func = func
        functools.update_wrapper(self, func)
        self._first_call = True
        self._not_cached = cache.NO_VALUE

    def _get_from_cache(self, target_self, *args, **kwargs):
        target_self_cls_name = reflection.get_class_name(target_self,
                                                         fully_qualified=False)
        func_name = "%(module)s.%(class)s.%(func_name)s" % {
            'module': target_self.__module__,
            'class': target_self_cls_name,
            'func_name': self.func.__name__,
        }
        key = (func_name,) + args
        if kwargs:
            key += utils.dict2tuple(kwargs)
        try:
            item = target_self._cache.get(key)
        except TypeError:
            LOG.debug("Method %(func_name)s cannot be cached due to "
                      "unhashable parameters: args: %(args)s, kwargs: "
                      "%(kwargs)s",
                      {'func_name': func_name,
                       'args': args,
                       'kwargs': kwargs})
            return self.func(target_self, *args, **kwargs)

        if item is self._not_cached:
            item = self.func(target_self, *args, **kwargs)
            target_self._cache.set(key, item)

        return item

    def __call__(self, target_self, *args, **kwargs):
        target_self_cls_name = reflection.get_class_name(target_self,
                                                         fully_qualified=False)
        if not hasattr(target_self, '_cache'):
            raise NotImplementedError(
                _("Instance of class %(module)s.%(class)s must contain _cache "
                  "attribute") % {
                    'module': target_self.__module__,
                    'class': target_self_cls_name})
        if not target_self._cache:
            if self._first_call:
                LOG.debug("Instance of class %(module)s.%(class)s doesn't "
                          "contain attribute _cache therefore results "
                          "cannot be cached for %(func_name)s.",
                          {'module': target_self.__module__,
                           'class': target_self_cls_name,
                           'func_name': self.func.__name__})
                self._first_call = False
            return self.func(target_self, *args, **kwargs)
        return self._get_from_cache(target_self, *args, **kwargs)

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)
