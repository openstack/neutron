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

import sqlalchemy as sql

from neutron.db import model_base
from neutron.openstack.common.db.sqlalchemy import session
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

BASE = model_base.BASEV2


def configure_db():
    """Configure database.

    Establish the database, create an engine if needed, and register
    the models.
    """
    session.get_engine(sqlite_fk=True)
    register_models()


def clear_db(base=BASE):
    unregister_models(base)
    session.cleanup()


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session."""
    return session.get_session(autocommit=autocommit,
                               expire_on_commit=expire_on_commit,
                               sqlite_fk=True)


def register_models(base=BASE):
    """Register Models and create properties."""
    try:
        engine = session.get_engine(sqlite_fk=True)
        base.metadata.create_all(engine)
    except sql.exc.OperationalError as e:
        LOG.info(_("Database registration exception: %s"), e)
        return False
    return True


def unregister_models(base=BASE):
    """Unregister Models, useful clearing out data before testing."""
    try:
        engine = session.get_engine(sqlite_fk=True)
        base.metadata.drop_all(engine)
    except Exception:
        LOG.exception(_("Database exception"))
