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

import time

from eventlet import db_pool
from eventlet import greenthread
try:
    import MySQLdb
except ImportError:
    MySQLdb = None
from oslo.config import cfg
import sqlalchemy as sql
from sqlalchemy import create_engine
from sqlalchemy.exc import DisconnectionError
from sqlalchemy.interfaces import PoolListener
from sqlalchemy.orm import sessionmaker

from quantum.db import model_base
from quantum.openstack.common import log as logging

LOG = logging.getLogger(__name__)
SQL_CONNECTION_DEFAULT = 'sqlite://'


database_opts = [
    cfg.StrOpt('sql_connection',
               help=_('The SQLAlchemy connection string used to connect to '
                      'the database'),
               secret=True),
    cfg.IntOpt('sql_max_retries', default=-1,
               help=_('Database reconnection retry times')),
    cfg.IntOpt('reconnect_interval', default=2,
               help=_('Database reconnection interval in seconds')),
    cfg.IntOpt('sql_min_pool_size',
               default=1,
               help=_("Minimum number of SQL connections to keep open in a "
                      "pool")),
    cfg.IntOpt('sql_max_pool_size',
               default=5,
               help=_("Maximum number of SQL connections to keep open in a "
                      "pool")),
    cfg.IntOpt('sql_idle_timeout',
               default=3600,
               help=_("Timeout in seconds before idle sql connections are "
                      "reaped")),
    cfg.BoolOpt('sql_dbpool_enable',
                default=False,
                help=_("Enable the use of eventlet's db_pool for MySQL")),
    cfg.IntOpt('sqlalchemy_pool_size',
               default=None,
               help=_("Maximum number of SQL connections to keep open in a "
                      "QueuePool in SQLAlchemy")),
    cfg.IntOpt('sqlalchemy_max_overflow',
               default=None,
               help=_("If set, use this value for max_overflow with "
                      "sqlalchemy")),
    cfg.IntOpt('sqlalchemy_pool_timeout',
               default=None,
               help=_("If set, use this value for pool_timeout with "
                      "sqlalchemy")),
]

cfg.CONF.register_opts(database_opts, "DATABASE")

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
                LOG.warn(_('Got mysql server has gone away: %s'), ex)
                raise DisconnectionError(_("Database server went away"))
            else:
                raise


class SqliteForeignKeysListener(PoolListener):
    """
    Ensures that the foreign key constraints are enforced in SQLite.

    The foreign key constraints are disabled by default in SQLite,
    so the foreign key constraints will be enabled here for every
    database connection
    """
    def connect(self, dbapi_con, con_record):
        dbapi_con.execute('pragma foreign_keys=ON')


def configure_db():
    """
    Establish the database, create an engine if needed, and
    register the models.
    """
    global _ENGINE
    if not _ENGINE:
        sql_connection = cfg.CONF.DATABASE.sql_connection
        if not sql_connection:
            LOG.warn(_("Option 'sql_connection' not specified "
                       "in any config file - using default "
                       "value '%s'" % SQL_CONNECTION_DEFAULT))
            sql_connection = SQL_CONNECTION_DEFAULT
        connection_dict = sql.engine.url.make_url(sql_connection)
        engine_args = {
            'pool_recycle': 3600,
            'echo': False,
            'convert_unicode': True,
        }

        if cfg.CONF.DATABASE.sqlalchemy_pool_size is not None:
            pool_size = cfg.CONF.DATABASE.sqlalchemy_pool_size
            engine_args['pool_size'] = pool_size
        if cfg.CONF.DATABASE.sqlalchemy_max_overflow is not None:
            max_overflow = cfg.CONF.DATABASE.sqlalchemy_max_overflow
            engine_args['max_overflow'] = max_overflow
        if cfg.CONF.DATABASE.sqlalchemy_pool_timeout is not None:
            pool_timeout = cfg.CONF.DATABASE.sqlalchemy_pool_timeout
            engine_args['pool_timeout'] = pool_timeout

        if 'mysql' in connection_dict.drivername:
            engine_args['listeners'] = [MySQLPingListener()]
            if (MySQLdb is not None and
                cfg.CONF.DATABASE.sql_dbpool_enable):
                pool_args = {
                    'db': connection_dict.database,
                    'passwd': connection_dict.password or '',
                    'host': connection_dict.host,
                    'user': connection_dict.username,
                    'min_size': cfg.CONF.DATABASE.sql_min_pool_size,
                    'max_size': cfg.CONF.DATABASE.sql_max_pool_size,
                    'max_idle': cfg.CONF.DATABASE.sql_idle_timeout
                }
                pool = db_pool.ConnectionPool(MySQLdb, **pool_args)

                def creator():
                    conn = pool.create()
                    # NOTE(belliott) eventlet >= 0.10 returns a tuple
                    if isinstance(conn, tuple):
                        _1, _2, conn = conn
                    return conn

                engine_args['creator'] = creator
            if (MySQLdb is None and cfg.CONF.DATABASE.sql_dbpool_enable):
                LOG.warn(_("Eventlet connection pooling will not work without "
                           "python-mysqldb!"))
        if 'sqlite' in connection_dict.drivername:
            engine_args['listeners'] = [SqliteForeignKeysListener()]
            if sql_connection == "sqlite://":
                engine_args["connect_args"] = {'check_same_thread': False}

        _ENGINE = create_engine(sql_connection, **engine_args)

        sql.event.listen(_ENGINE, 'checkin', greenthread_yield)

        if not register_models():
            if cfg.CONF.DATABASE.reconnect_interval:
                remaining = cfg.CONF.DATABASE.sql_max_retries
                reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
                retry_registration(remaining, reconnect_interval)


def clear_db(base=BASE):
    global _ENGINE, _MAKER
    assert _ENGINE

    unregister_models(base)
    if _MAKER:
        _MAKER.close_all()
        _MAKER = None
    _ENGINE.dispose()
    _ENGINE = None


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
                LOG.error(_("Database connection lost, exit..."))
                break
            remaining -= 1
        LOG.info(_("Unable to connect to database, %(remaining)s attempts "
                   "left. Retrying in %(reconnect_interval)s seconds"),
                 locals())
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
        LOG.info(_("Database registration exception: %s"), e)
        return False
    return True


def unregister_models(base=BASE):
    """Unregister Models, useful clearing out data before testing"""
    global _ENGINE
    assert _ENGINE
    base.metadata.drop_all(_ENGINE)


def greenthread_yield(dbapi_con, con_record):
    """
    Ensure other greenthreads get a chance to execute by forcing a context
    switch. With common database backends (eg MySQLdb and sqlite), there is
    no implicit yield caused by network I/O since they are implemented by
    C libraries that eventlet cannot monkey patch.
    """
    greenthread.sleep(0)
