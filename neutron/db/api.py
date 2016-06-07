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
import sqlalchemy
from sqlalchemy.orm import exc

from neutron.common import exceptions
from neutron.common import profiler  # noqa

context_manager = enginefacade.transaction_context()


_FACADE = None

MAX_RETRIES = 10


def is_retriable(e):
    if _is_nested_instance(e, (db_exc.DBDeadlock, exc.StaleDataError)):
        return True
    # looking savepoints mangled by deadlocks. see bug/1590298 for details.
    return _is_nested_instance(e, db_exc.DBError) and '1305' in str(e)

is_deadlock = moves.moved_function(is_retriable, 'is_deadlock', __name__,
                                   message='use "is_retriable" instead',
                                   version='newton', removal_version='ocata')
retry_db_errors = oslo_db_api.wrap_db_retry(
    max_retries=MAX_RETRIES,
    retry_on_request=True,
    exception_checker=is_retriable
)


def _is_nested_instance(e, etypes):
    """Check if exception or its inner excepts are an instance of etypes."""
    return (isinstance(e, etypes) or
            isinstance(e, exceptions.MultipleExceptions) and
            any(_is_nested_instance(i, etypes) for i in e.inner_exceptions))


@contextlib.contextmanager
def exc_to_retry(exceptions):
    try:
        yield
    except Exception as e:
        with excutils.save_and_reraise_exception() as ctx:
            if _is_nested_instance(e, exceptions):
                ctx.reraise = False
                raise db_exc.RetryRequest(e)


def _create_facade_lazily():
    global _FACADE

    if _FACADE is None:
        context_manager.configure(sqlite_fk=True, **cfg.CONF.database)
        _FACADE = context_manager._factory.get_legacy_facade()

        if cfg.CONF.profiler.enabled and cfg.CONF.profiler.trace_sqlalchemy:
            osprofiler.sqlalchemy.add_tracing(sqlalchemy,
                                              _FACADE.get_engine(),
                                              "db")

    return _FACADE


def get_engine():
    """Helper method to grab engine."""
    facade = _create_facade_lazily()
    return facade.get_engine()


def dispose():
    # Don't need to do anything if an enginefacade hasn't been created
    if _FACADE is not None:
        get_engine().pool.dispose()


def get_session(autocommit=True, expire_on_commit=False, use_slave=False):
    """Helper method to grab session."""
    facade = _create_facade_lazily()
    return facade.get_session(autocommit=autocommit,
                              expire_on_commit=expire_on_commit,
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
