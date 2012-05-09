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

from quantum.api.api_common import OperationalStatus
from quantum.common import exceptions as q_exc
from quantum.db import model_base, models


LOG = logging.getLogger(__name__)


_ENGINE = None
_MAKER = None
BASE = model_base.BASE


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
                retry_registration(options['reconnect_interval'], base)


def clear_db(base=BASE):
    global _ENGINE
    assert _ENGINE
    for table in reversed(base.metadata.sorted_tables):
        _ENGINE.execute(table.delete())


def get_session(autocommit=True, expire_on_commit=False):
    """Helper method to grab session"""
    global _MAKER, _ENGINE
    if not _MAKER:
        assert _ENGINE
        _MAKER = sessionmaker(bind=_ENGINE,
                              autocommit=autocommit,
                              expire_on_commit=expire_on_commit)
    return _MAKER()


def retry_registration(reconnect_interval, base=BASE):
    while True:
        LOG.info("Unable to connect to database. Retrying in %s seconds" %
                 reconnect_interval)
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


def network_create(tenant_id, name, op_status=OperationalStatus.UNKNOWN):
    session = get_session()

    with session.begin():
        net = models.Network(tenant_id, name, op_status)
        session.add(net)
        session.flush()
        return net


def network_all_tenant_list():
    session = get_session()
    return session.query(models.Network).all()


def network_list(tenant_id):
    session = get_session()
    return (session.query(models.Network).
            filter_by(tenant_id=tenant_id).
            all())


def network_get(net_id):
    session = get_session()
    try:
        return (session.query(models.Network).
                filter_by(uuid=net_id).
                one())
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=net_id)


def network_update(net_id, tenant_id, **kwargs):
    session = get_session()
    net = network_get(net_id)
    for key in kwargs.keys():
        net[key] = kwargs[key]
    session.merge(net)
    session.flush()
    return net


def network_destroy(net_id):
    session = get_session()
    try:
        net = (session.query(models.Network).
               filter_by(uuid=net_id).
               one())

        ports = (session.query(models.Port).
                 filter_by(network_id=net_id).
                 all())
        for p in ports:
            session.delete(p)

        session.delete(net)
        session.flush()
        return net
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=net_id)


def validate_network_ownership(tenant_id, net_id):
    session = get_session()
    try:
        return (session.query(models.Network).
                filter_by(uuid=net_id).
                filter_by(tenant_id=tenant_id).
                one())
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=net_id)


def port_create(net_id, state=None, op_status=OperationalStatus.UNKNOWN):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    with session.begin():
        port = models.Port(net_id, op_status)
        if state is None:
            state = 'DOWN'
        elif state not in ('ACTIVE', 'DOWN'):
            raise q_exc.StateInvalid(port_state=state)
        port['state'] = state
        session.add(port)
        session.flush()
        return port


def port_list(net_id):
    # confirm network exists
    network_get(net_id)
    session = get_session()
    return (session.query(models.Port).
            filter_by(network_id=net_id).
            all())


def port_get(port_id, net_id, session=None):
    # confirm network exists
    network_get(net_id)
    if not session:
        session = get_session()
    try:
        return (session.query(models.Port).
                filter_by(uuid=port_id).
                filter_by(network_id=net_id).
                one())
    except exc.NoResultFound:
        raise q_exc.PortNotFound(net_id=net_id, port_id=port_id)


def port_update(port_id, net_id, **kwargs):
    # confirm network exists
    network_get(net_id)
    port = port_get(port_id, net_id)
    session = get_session()
    for key in kwargs:
        if key == "state":
            if kwargs[key] not in ('ACTIVE', 'DOWN'):
                raise q_exc.StateInvalid(port_state=kwargs[key])
        port[key] = kwargs[key]
    session.merge(port)
    session.flush()
    return port


def port_set_attachment(port_id, net_id, new_interface_id):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    port = port_get(port_id, net_id)

    if new_interface_id != "":
        # We are setting, not clearing, the attachment-id
        if port['interface_id']:
            raise q_exc.PortInUse(net_id=net_id, port_id=port_id,
                                  att_id=port['interface_id'])

        try:
            port = (session.query(models.Port).
                    filter_by(interface_id=new_interface_id).
                    one())
            raise q_exc.AlreadyAttached(net_id=net_id,
                                        port_id=port_id,
                                        att_id=new_interface_id,
                                        att_port_id=port['uuid'])
        except exc.NoResultFound:
            # this is what should happen
            pass
    port.interface_id = new_interface_id
    session.merge(port)
    session.flush()
    return port


def port_unset_attachment(port_id, net_id):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    port = port_get(port_id, net_id, session)
    port.interface_id = None
    session.add(port)
    session.flush()


def port_destroy(port_id, net_id):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    try:
        port = (session.query(models.Port).
                filter_by(uuid=port_id).
                filter_by(network_id=net_id).
                one())
        if port['interface_id']:
            raise q_exc.PortInUse(net_id=net_id, port_id=port_id,
                                  att_id=port['interface_id'])
        session.delete(port)
        session.flush()
        return port
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)


def validate_port_ownership(tenant_id, net_id, port_id, session=None):
    validate_network_ownership(tenant_id, net_id)
    port_get(port_id, net_id)
