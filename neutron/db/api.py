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

import contextlib

from debtcollector import moves
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_db.sqlalchemy import enginefacade
from oslo_utils import excutils
import osprofiler.sqlalchemy
import six
import sqlalchemy
from sqlalchemy.orm import exc

from neutron.common import exceptions
from neutron.common import profiler  # noqa

context_manager = enginefacade.transaction_context()
context_manager.configure(sqlite_fk=True)

_PROFILER_INITIALIZED = False

MAX_RETRIES = 10


def is_retriable(e):
    if _is_nested_instance(e, (db_exc.DBDeadlock, exc.StaleDataError,
                               db_exc.DBDuplicateEntry, db_exc.RetryRequest)):
        return True
    # looking savepoints mangled by deadlocks. see bug/1590298 for details.
    return _is_nested_instance(e, db_exc.DBError) and '1305' in str(e)

is_deadlock = moves.moved_function(is_retriable, 'is_deadlock', __name__,
                                   message='use "is_retriable" instead',
                                   version='newton', removal_version='ocata')
retry_db_errors = oslo_db_api.wrap_db_retry(
    max_retries=MAX_RETRIES,
    retry_interval=0.1,
    inc_retry_interval=True,
    exception_checker=is_retriable
)


def reraise_as_retryrequest(f):
    """Packs retriable exceptions into a RetryRequest."""

    @six.wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctx:
                if is_retriable(e):
                    ctx.reraise = False
                    raise db_exc.RetryRequest(e)
    return wrapped


def _is_nested_instance(e, etypes):
    """Check if exception or its inner excepts are an instance of etypes."""
    return (isinstance(e, etypes) or
            isinstance(e, exceptions.MultipleExceptions) and
            any(_is_nested_instance(i, etypes) for i in e.inner_exceptions))


# TODO(akamyshnikova) this code should be in oslo.db
def _set_profiler():
    global _PROFILER_INITIALIZED
    if (not _PROFILER_INITIALIZED and cfg.CONF.profiler.enabled and
            cfg.CONF.profiler.trace_sqlalchemy):
        _PROFILER_INITIALIZED = True
        osprofiler.sqlalchemy.add_tracing(
            sqlalchemy, context_manager.get_legacy_facade().get_engine(), "db")


@contextlib.contextmanager
def exc_to_retry(exceptions):
    try:
        yield
    except Exception as e:
        with excutils.save_and_reraise_exception() as ctx:
            if _is_nested_instance(e, exceptions):
                ctx.reraise = False
                raise db_exc.RetryRequest(e)


#TODO(akamyshnikova): when all places in the code, which use sessions/
# connections will be updated, this won't be needed
def get_engine():
    """Helper method to grab engine."""
    _set_profiler()
    return context_manager.get_legacy_facade().get_engine()


def dispose():
    # TODO(akamyshnikova): Use context_manager.dispose_pool() when it is
    #                      available in oslo.db
    if context_manager._factory._started:
        get_engine().pool.dispose()


#TODO(akamyshnikova): when all places in the code, which use sessions/
# connections will be updated, this won't be needed
def get_session(autocommit=True, expire_on_commit=False, use_slave=False):
    """Helper method to grab session."""
    _set_profiler()
    return context_manager.get_legacy_facade().get_session(
        autocommit=autocommit, expire_on_commit=expire_on_commit,
        use_slave=use_slave)


@contextlib.contextmanager
def autonested_transaction(sess):
    """This is a convenience method to not bother with 'nested' parameter."""
    if sess.is_active:
        session_context = sess.begin(nested=True)
    else:
        session_context = sess.begin(subtransactions=True)
    with session_context as tx:
        yield tx
