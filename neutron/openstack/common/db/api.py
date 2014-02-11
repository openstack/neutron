# Copyright (c) 2013 Rackspace Hosting
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

"""Multiple DB API backend support.

Supported configuration options:

The following two parameters are in the 'database' group:
`backend`: DB backend name or full module path to DB backend module.

A DB backend module should implement a method named 'get_backend' which
takes no arguments.  The method can return any object that implements DB
API methods.
"""

import functools
import logging
import time

from oslo.config import cfg

from neutron.openstack.common.db import exception
from neutron.openstack.common.gettextutils import _  # noqa
from neutron.openstack.common import importutils


db_opts = [
    cfg.StrOpt('backend',
               default='sqlalchemy',
               deprecated_name='db_backend',
               deprecated_group='DEFAULT',
               help='The backend to use for db'),
    cfg.BoolOpt('use_db_reconnect',
                default=False,
                help='Enable the experimental use of database reconnect '
                     'on connection lost'),
    cfg.IntOpt('db_retry_interval',
               default=1,
               help='seconds between db connection retries'),
    cfg.BoolOpt('db_inc_retry_interval',
                default=True,
                help='Whether to increase interval between db connection '
                     'retries, up to db_max_retry_interval'),
    cfg.IntOpt('db_max_retry_interval',
               default=10,
               help='max seconds between db connection retries, if '
                    'db_inc_retry_interval is enabled'),
    cfg.IntOpt('db_max_retries',
               default=20,
               help='maximum db connection retries before error is raised. '
                    '(setting -1 implies an infinite retry count)'),
]

CONF = cfg.CONF
CONF.register_opts(db_opts, 'database')

LOG = logging.getLogger(__name__)


def safe_for_db_retry(f):
    """Enable db-retry for decorated function, if config option enabled."""
    f.__dict__['enable_retry'] = True
    return f


def _wrap_db_retry(f):
    """Retry db.api methods, if DBConnectionError() raised

    Retry decorated db.api methods. If we enabled `use_db_reconnect`
    in config, this decorator will be applied to all db.api functions,
    marked with @safe_for_db_retry decorator.
    Decorator catchs DBConnectionError() and retries function in a
    loop until it succeeds, or until maximum retries count will be reached.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        next_interval = CONF.database.db_retry_interval
        remaining = CONF.database.db_max_retries

        while True:
            try:
                return f(*args, **kwargs)
            except exception.DBConnectionError as e:
                if remaining == 0:
                    LOG.exception(_('DB exceeded retry limit.'))
                    raise exception.DBError(e)
                if remaining != -1:
                    remaining -= 1
                    LOG.exception(_('DB connection error.'))
                # NOTE(vsergeyev): We are using patched time module, so this
                #                  effectively yields the execution context to
                #                  another green thread.
                time.sleep(next_interval)
                if CONF.database.db_inc_retry_interval:
                    next_interval = min(
                        next_interval * 2,
                        CONF.database.db_max_retry_interval
                    )
    return wrapper


class DBAPI(object):
    def __init__(self, backend_mapping=None):
        if backend_mapping is None:
            backend_mapping = {}
        backend_name = CONF.database.backend
        # Import the untranslated name if we don't have a
        # mapping.
        backend_path = backend_mapping.get(backend_name, backend_name)
        backend_mod = importutils.import_module(backend_path)
        self.__backend = backend_mod.get_backend()

    def __getattr__(self, key):
        attr = getattr(self.__backend, key)

        if not hasattr(attr, '__call__'):
            return attr
        # NOTE(vsergeyev): If `use_db_reconnect` option is set to True, retry
        #                  DB API methods, decorated with @safe_for_db_retry
        #                  on disconnect.
        if CONF.database.use_db_reconnect and hasattr(attr, 'enable_retry'):
            attr = _wrap_db_retry(attr)

        return attr
