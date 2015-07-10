# Copyright 2011 VMware, Inc.
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

import six
import sys
import time

from oslo.config import cfg
from oslo.db import exception as oslo_db_exc
from oslo.db.sqlalchemy import session

from neutron.common import exceptions as exc
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

_FACADE = None

MAX_RETRIES = 10


def _create_facade_lazily():
    global _FACADE

    if _FACADE is None:
        _FACADE = session.EngineFacade.from_config(cfg.CONF, sqlite_fk=True)

    return _FACADE


def get_engine():
    """Helper method to grab engine."""
    facade = _create_facade_lazily()
    return facade.get_engine()


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session."""
    facade = _create_facade_lazily()
    return facade.get_session(autocommit=autocommit,
                              expire_on_commit=expire_on_commit)


class wrap_db_retry(object):
    """Retry db.api methods, if db_error raised

    Retry decorated db.api methods. This decorator catches db_error and retries
    function in a loop until it succeeds, or until maximum retries count
    will be reached.

    Keyword arguments:

    :param retry_interval: seconds between transaction retries
    :type retry_interval: int

    :param max_retries: max number of retries before an error is raised
    :type max_retries: int

    :param inc_retry_interval: determine increase retry interval or not
    :type inc_retry_interval: bool

    :param max_retry_interval: max interval value between retries
    :type max_retry_interval: int
    """

    def __init__(self, retry_interval=0, max_retries=0, inc_retry_interval=0,
                 max_retry_interval=0, retry_on_disconnect=False,
                 retry_on_deadlock=False, retry_on_request=False):
        super(wrap_db_retry, self).__init__()

        self.db_error = ()
        if retry_on_disconnect:
            self.db_error += (oslo_db_exc.DBConnectionError, )
        if retry_on_deadlock:
            self.db_error += (oslo_db_exc.DBDeadlock, )
        if retry_on_request:
            self.db_error += (exc.RetryRequest, )
        self.retry_interval = retry_interval
        self.max_retries = max_retries
        self.inc_retry_interval = inc_retry_interval
        self.max_retry_interval = max_retry_interval

    def __call__(self, f):
        @six.wraps(f)
        def wrapper(*args, **kwargs):
            next_interval = self.retry_interval
            remaining = self.max_retries
            db_error = self.db_error

            while True:
                try:
                    return f(*args, **kwargs)
                except db_error as e:
                    if remaining == 0:
                        LOG.exception(_('DB exceeded retry limit.'))
                        if isinstance(e, exc.RetryRequest):
                            six.reraise(type(e.inner_exc),
                                        e.inner_exc,
                                        sys.exc_info()[2])
                        raise e
                    if remaining != -1:
                        remaining -= 1
                        LOG.exception(_('DB error.'))
                    # NOTE(vsergeyev): We are using patched time module, so
                    #                  this effectively yields the execution
                    #                  context to another green thread.
                    time.sleep(next_interval)
                    if self.inc_retry_interval:
                        next_interval = min(
                            next_interval * 2,
                            self.max_retry_interval
                        )
        return wrapper
