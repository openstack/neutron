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

from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_db.sqlalchemy import session
from oslo_utils import excutils
from oslo_utils import uuidutils
from sqlalchemy import exc

from neutron.common import exceptions as n_exc
from neutron.db import common_db_mixin


_FACADE = None

MAX_RETRIES = 10
is_deadlock = lambda e: isinstance(e, db_exc.DBDeadlock)
retry_db_errors = oslo_db_api.wrap_db_retry(
    max_retries=MAX_RETRIES,
    retry_on_request=True,
    exception_checker=is_deadlock
)


@contextlib.contextmanager
def exc_to_retry(exceptions):
    try:
        yield
    except Exception as e:
        with excutils.save_and_reraise_exception() as ctx:
            if isinstance(e, exceptions):
                ctx.reraise = False
                raise db_exc.RetryRequest(e)


def _create_facade_lazily():
    global _FACADE

    if _FACADE is None:
        _FACADE = session.EngineFacade.from_config(cfg.CONF, sqlite_fk=True)

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
    try:
        session_context = sess.begin_nested()
    except exc.InvalidRequestError:
        session_context = sess.begin(subtransactions=True)
    finally:
        with session_context as tx:
            yield tx


# Common database operation implementations
def get_object(context, model, **kwargs):
    with context.session.begin(subtransactions=True):
        return (common_db_mixin.model_query(context, model)
                .filter_by(**kwargs)
                .first())


def get_objects(context, model, **kwargs):
    with context.session.begin(subtransactions=True):
        return (common_db_mixin.model_query(context, model)
                .filter_by(**kwargs)
                .all())


def create_object(context, model, values):
    with context.session.begin(subtransactions=True):
        if 'id' not in values:
            values['id'] = uuidutils.generate_uuid()
        db_obj = model(**values)
        context.session.add(db_obj)
    return db_obj.__dict__


def _safe_get_object(context, model, id):
    db_obj = get_object(context, model, id=id)
    if db_obj is None:
        raise n_exc.ObjectNotFound(id=id)
    return db_obj


def update_object(context, model, id, values):
    with context.session.begin(subtransactions=True):
        db_obj = _safe_get_object(context, model, id)
        db_obj.update(values)
        db_obj.save(session=context.session)
    return db_obj.__dict__


def delete_object(context, model, id):
    with context.session.begin(subtransactions=True):
        db_obj = _safe_get_object(context, model, id)
        context.session.delete(db_obj)
