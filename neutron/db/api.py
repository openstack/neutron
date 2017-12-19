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
import copy
import weakref

from neutron_lib.db import api
from neutron_lib import exceptions
from neutron_lib.objects import exceptions as obj_exc
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from osprofiler import opts as profiler_opts
import osprofiler.sqlalchemy
from pecan import util as p_util
import six
import sqlalchemy
from sqlalchemy import event  # noqa
from sqlalchemy import exc as sql_exc
from sqlalchemy import orm
from sqlalchemy.orm import exc


def set_hook(engine):
    if (profiler_opts.is_trace_enabled() and
            profiler_opts.is_db_trace_enabled()):
        osprofiler.sqlalchemy.add_tracing(sqlalchemy, engine, 'neutron.db')


context_manager = api.get_context_manager()

# TODO(ihrachys) the hook assumes options defined by osprofiler, and the only
# public function that is provided by osprofiler that will register them is
# set_defaults, that's why we call it here even though we don't need to change
# defaults
profiler_opts.set_defaults(cfg.CONF)
context_manager.append_on_engine_create(set_hook)


MAX_RETRIES = 10
LOG = logging.getLogger(__name__)


def is_retriable(e):
    if getattr(e, '_RETRY_EXCEEDED', False):
        return False
    if _is_nested_instance(e, (db_exc.DBDeadlock, exc.StaleDataError,
                               db_exc.DBConnectionError,
                               db_exc.DBDuplicateEntry, db_exc.RetryRequest,
                               obj_exc.NeutronDbObjectDuplicateEntry)):
        return True
    # looking savepoints mangled by deadlocks. see bug/1590298 for details.
    return _is_nested_instance(e, db_exc.DBError) and '1305' in str(e)

_retry_db_errors = oslo_db_api.wrap_db_retry(
    max_retries=MAX_RETRIES,
    retry_interval=0.1,
    inc_retry_interval=True,
    exception_checker=is_retriable
)


def _tag_retriables_as_unretriable(f):
    """Puts a flag on retriable exceptions so is_retriable returns False.

    This decorator can be used outside of a retry decorator to prevent
    decorators higher up from retrying again.
    """
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if is_retriable(e):
                    setattr(e, '_RETRY_EXCEEDED', True)
    return wrapped


def _copy_if_lds(item):
    """Deepcopy lists/dicts/sets, leave everything else alone."""
    return copy.deepcopy(item) if isinstance(item, (list, dict, set)) else item


def retry_db_errors(f):
    """Nesting-safe retry decorator with auto-arg-copy and logging.

    Retry decorator for all functions which do not accept a context as an
    argument. If the function accepts a context, use
    'retry_if_session_inactive' below.

    If retriable errors are retried and exceed the count, they will be tagged
    with a flag so is_retriable will no longer recognize them as retriable.
    This prevents multiple applications of this decorator (and/or the one
    below) from retrying the same exception.
    """

    @_tag_retriables_as_unretriable
    @_retry_db_errors
    @six.wraps(f)
    def wrapped(*args, **kwargs):
        try:
            # copy mutable args and kwargs to make retries safe. this doesn't
            # prevent mutations of complex objects like the context or 'self'
            dup_args = [_copy_if_lds(a) for a in args]
            dup_kwargs = {k: _copy_if_lds(v) for k, v in kwargs.items()}
            return f(*dup_args, **dup_kwargs)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if is_retriable(e):
                    LOG.debug("Retry wrapper got retriable exception: %s", e)
    return wrapped


def retry_if_session_inactive(context_var_name='context'):
    """Retries only if the session in the context is inactive.

    Calls a retry_db_errors wrapped version of the function if the context's
    session passed in is inactive, otherwise it just calls the function
    directly. This is useful to avoid retrying things inside of a transaction
    which is ineffective for DB races/errors.

    This should be used in all cases where retries are desired and the method
    accepts a context.
    """
    def decorator(f):
        try:
            # NOTE(kevinbenton): we use pecan's util function here because it
            # deals with the horrors of finding args of already decorated
            # functions
            ctx_arg_index = p_util.getargspec(f).args.index(context_var_name)
        except ValueError:
            raise RuntimeError("Could not find position of var %s" %
                               context_var_name)
        f_with_retry = retry_db_errors(f)

        @six.wraps(f)
        def wrapped(*args, **kwargs):
            # only use retry wrapper if we aren't nested in an active
            # transaction
            if context_var_name in kwargs:
                context = kwargs[context_var_name]
            else:
                context = args[ctx_arg_index]
            method = f if context.session.is_active else f_with_retry
            return method(*args, **kwargs)
        return wrapped
    return decorator


def _is_nested_instance(e, etypes):
    """Check if exception or its inner excepts are an instance of etypes."""
    if isinstance(e, etypes):
        return True
    if isinstance(e, exceptions.MultipleExceptions):
        return any(_is_nested_instance(i, etypes) for i in e.inner_exceptions)
    if isinstance(e, db_exc.DBError):
        return _is_nested_instance(e.inner_exception, etypes)
    return False


@contextlib.contextmanager
def exc_to_retry(etypes):
    try:
        yield
    except Exception as e:
        with excutils.save_and_reraise_exception() as ctx:
            if _is_nested_instance(e, etypes):
                ctx.reraise = False
                raise db_exc.RetryRequest(e)


def get_reader_session():
    """Helper to get reader session"""
    return context_manager.reader.get_sessionmaker()()


def get_writer_session():
    """Helper to get writer session"""
    return context_manager.writer.get_sessionmaker()()


@contextlib.contextmanager
def autonested_transaction(sess):
    """This is a convenience method to not bother with 'nested' parameter."""
    if sess.is_active:
        session_context = sess.begin(nested=True)
    else:
        session_context = sess.begin(subtransactions=True)
    with session_context as tx:
        yield tx


_REGISTERED_SQLA_EVENTS = []


def sqla_listen(*args):
    """Wrapper to track subscribers for test teardowns.

    SQLAlchemy has no "unsubscribe all" option for its event listener
    framework so we need to keep track of the subscribers by having
    them call through here for test teardowns.
    """
    event.listen(*args)
    _REGISTERED_SQLA_EVENTS.append(args)


def sqla_remove(*args):
    event.remove(*args)
    _REGISTERED_SQLA_EVENTS.remove(args)


def sqla_remove_all():
    for args in _REGISTERED_SQLA_EVENTS:
        try:
            event.remove(*args)
        except sql_exc.InvalidRequestError:
            # already removed
            pass
    del _REGISTERED_SQLA_EVENTS[:]


@event.listens_for(orm.session.Session, "after_flush")
def add_to_rel_load_list(session, flush_context=None):
    # keep track of new items to load relationships on during commit
    session.info.setdefault('_load_rels', weakref.WeakSet()).update(
        session.new)


@event.listens_for(orm.session.Session, "before_commit")
def load_one_to_manys(session):
    # TODO(kevinbenton): we should be able to remove this after we
    # have eliminated all places where related objects are constructed
    # using a key rather than a relationship.

    # capture any new objects
    if session.new:
        session.flush()

    if session.transaction.nested:
        # wait until final commit
        return

    for new_object in session.info.pop('_load_rels', []):
        if new_object not in session:
            # don't load detached objects because that brings them back into
            # session
            continue
        state = sqlalchemy.inspect(new_object)

        # set up relationship loading so that we can call lazy
        # loaders on the object even though the ".key" is not set up yet
        # (normally happens by in after_flush_postexec, but we're trying
        # to do this more succinctly).  in this context this is only
        # setting a simple flag on the object's state.
        session.enable_relationship_loading(new_object)

        # look for eager relationships and do normal load.
        # For relationships where the related object is also
        # in the session these lazy loads will pull from the
        # identity map and not emit SELECT.  Otherwise, we are still
        # local in the transaction so a normal SELECT load will work fine.
        for relationship_attr in state.mapper.relationships:
            if relationship_attr.lazy not in ('joined', 'subquery'):
                # we only want to automatically load relationships that would
                # automatically load during a lookup operation
                continue
            if relationship_attr.key not in state.dict:
                getattr(new_object, relationship_attr.key)
                assert relationship_attr.key in state.dict
