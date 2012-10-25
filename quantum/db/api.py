# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.

import logging
import time

import sqlalchemy as sql
from sqlalchemy import create_engine
from sqlalchemy.exc import DisconnectionError
from sqlalchemy.orm import sessionmaker, exc

from quantum.db import model_base

LOG = logging.getLogger(__name__)


_ENGINE = None
_MAKER = None
BASE = model_base.BASEV2


class MySQLPingListener(object):

    """
    Ensures that MySQL connections checked out of the
    pool are alive.

    Borrowed from:
    http://groups.google.com/group/sqlalchemy/msg/a4ce563d802c929f
    """

    def checkout(self, dbapi_con, con_record, con_proxy):
        try:
            dbapi_con.cursor().execute('select 1')
        except dbapi_con.OperationalError, ex:
            if ex.args[0] in (2006, 2013, 2014, 2045, 2055):
                LOG.warn('Got mysql server has gone away: %s', ex)
                raise DisconnectionError("Database server went away")
            else:
                raise


def configure_db(options):
    """
    Establish the database, create an engine if needed, and
    register the models.

    :param options: Mapping of configuration options
    """
    global _ENGINE
    if not _ENGINE:
        connection_dict = sql.engine.url.make_url(options['sql_connection'])
        engine_args = {
            'pool_recycle': 3600,
            'echo': False,
            'convert_unicode': True,
        }

        if 'mysql' in connection_dict.drivername:
            engine_args['listeners'] = [MySQLPingListener()]

        _ENGINE = create_engine(options['sql_connection'], **engine_args)
        base = options.get('base', BASE)
        if not register_models(base):
            if 'reconnect_interval' in options:
                remaining = options.get('sql_max_retries', -1)
                reconnect_interval = options['reconnect_interval']
                retry_registration(remaining, reconnect_interval, base)


def clear_db(base=BASE):
    global _ENGINE
    assert _ENGINE
    for table in reversed(base.metadata.sorted_tables):
        try:
            _ENGINE.execute(table.delete())
        except Exception as e:
            LOG.info("Unable to delete table. %s.", e)


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
    global _MAKER, _ENGINE
    if not _MAKER:
        assert _ENGINE
        _MAKER = sessionmaker(bind=_ENGINE,
                              autocommit=autocommit,
                              expire_on_commit=expire_on_commit)
    return _MAKER()


def retry_registration(remaining, reconnect_interval, base=BASE):
    if remaining == -1:
        remaining = 'infinite'
    while True:
        if remaining != 'infinite':
            if remaining == 0:
                LOG.error("Database connection lost, exit...")
                break
            remaining -= 1
        LOG.info("Unable to connect to database, %s attempts left. "
                 "Retrying in %s seconds" % (remaining, reconnect_interval))
        time.sleep(reconnect_interval)
        if register_models(base):
            break


def register_models(base=BASE):
    """Register Models and create properties"""
    global _ENGINE
    assert _ENGINE
    try:
        base.metadata.create_all(_ENGINE)
    except sql.exc.OperationalError as e:
        LOG.info("Database registration exception: %s" % e)
        return False
    return True


def unregister_models(base=BASE):
    """Unregister Models, useful clearing out data before testing"""
    global _ENGINE
    assert _ENGINE
    base.metadata.drop_all(_ENGINE)
