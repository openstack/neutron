# Copyright 2013 Red Hat, Inc.
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

"""Cache library.

Supported configuration options:

`default_backend`: Name of the cache backend to use.
`key_namespace`: Namespace under which keys will be created.
"""

########################################################################
#
# THIS MODULE IS DEPRECATED
#
# Please refer to
# https://etherpad.openstack.org/p/kilo-neutron-library-proposals for
# the discussion leading to this deprecation.
#
# We recommend helping with the new neutron.cache library being created
# as a wrapper for dogpile.
#
########################################################################


from six.moves.urllib import parse
from stevedore import driver


def _get_oslo_configs():
    """Returns the oslo.config options to register."""
    # NOTE(flaper87): Oslo config should be
    # optional. Instead of doing try / except
    # at the top of this file, lets import cfg
    # here and assume that the caller of this
    # function already took care of this dependency.
    from oslo.config import cfg

    return [
        cfg.StrOpt('cache_url', default='memory://',
                   help='URL to connect to the cache back end.')
    ]


def register_oslo_configs(conf):
    """Registers a cache configuration options

    :params conf: Config object.
    :type conf: `cfg.ConfigOptions`
    """
    conf.register_opts(_get_oslo_configs())


def get_cache(url='memory://'):
    """Loads the cache backend

    This function loads the cache backend
    specified in the given configuration.

    :param conf: Configuration instance to use
    """

    parsed = parse.urlparse(url)
    backend = parsed.scheme

    query = parsed.query
    # NOTE(flaper87): We need the following hack
    # for python versions < 2.7.5. Previous versions
    # of python parsed query params just for 'known'
    # schemes. This was changed in this patch:
    # http://hg.python.org/cpython/rev/79e6ff3d9afd
    if not query and '?' in parsed.path:
        query = parsed.path.split('?', 1)[-1]
    parameters = parse.parse_qsl(query)
    kwargs = {'options': dict(parameters)}

    mgr = driver.DriverManager('neutron.openstack.common.cache.backends', backend,
                               invoke_on_load=True,
                               invoke_args=[parsed],
                               invoke_kwds=kwargs)
    return mgr.driver
