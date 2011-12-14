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

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, exc

from quantum.api.api_common import OperationalStatus
from quantum.common import exceptions as q_exc
from quantum.db import models


_ENGINE = None
_MAKER = None
BASE = models.BASE
LOG = logging.getLogger('quantum.db.api')


def configure_db(options):
    """
    Establish the database, create an engine if needed, and
    register the models.

    :param options: Mapping of configuration options
    """
    global _ENGINE
    if not _ENGINE:
        _ENGINE = create_engine(options['sql_connection'],
                                echo=False,
                                echo_pool=True,
                                pool_recycle=3600)
        register_models()


def clear_db():
    global _ENGINE
    assert _ENGINE
    for table in reversed(BASE.metadata.sorted_tables):
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


def register_models():
    """Register Models and create properties"""
    global _ENGINE
    assert _ENGINE
    BASE.metadata.create_all(_ENGINE)


def unregister_models():
    """Unregister Models, useful clearing out data before testing"""
    global _ENGINE
    assert _ENGINE
    BASE.metadata.drop_all(_ENGINE)


def network_create(tenant_id, name, op_status=OperationalStatus.UNKNOWN):
    session = get_session()

    with session.begin():
        net = models.Network(tenant_id, name, op_status)
        session.add(net)
        session.flush()
        return net


def network_list(tenant_id):
    session = get_session()
    return session.query(models.Network).\
      filter_by(tenant_id=tenant_id).\
      all()


def network_get(net_id):
    session = get_session()
    try:
        return  session.query(models.Network).\
            filter_by(uuid=net_id).\
            one()
    except exc.NoResultFound, e:
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
        net = session.query(models.Network).\
          filter_by(uuid=net_id).\
          one()

        ports = session.query(models.Port).\
            filter_by(network_id=net_id).\
            all()
        for p in ports:
            session.delete(p)

        session.delete(net)
        session.flush()
        return net
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=net_id)


def port_create(net_id, state=None, op_status=OperationalStatus.UNKNOWN):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    with session.begin():
        port = models.Port(net_id, op_status)
        port['state'] = state or 'DOWN'
        session.add(port)
        session.flush()
        return port


def port_list(net_id):
    # confirm network exists
    network_get(net_id)
    session = get_session()
    return session.query(models.Port).\
      filter_by(network_id=net_id).\
      all()


def port_get(port_id, net_id, session=None):
    # confirm network exists
    network_get(net_id)
    if not session:
        session = get_session()
    try:
        return session.query(models.Port).\
          filter_by(uuid=port_id).\
          filter_by(network_id=net_id).\
          one()
    except exc.NoResultFound:
        raise q_exc.PortNotFound(net_id=net_id, port_id=port_id)


def port_update(port_id, net_id, **kwargs):
    # confirm network exists
    network_get(net_id)
    port = port_get(port_id, net_id)
    session = get_session()
    for key in kwargs.keys():
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
            port = session.query(models.Port).\
            filter_by(interface_id=new_interface_id).\
            one()
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
        port = session.query(models.Port).\
          filter_by(uuid=port_id).\
          filter_by(network_id=net_id).\
          one()
        if port['interface_id']:
            raise q_exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])
        session.delete(port)
        session.flush()
        return port
    except exc.NoResultFound:
        raise q_exc.PortNotFound(port_id=port_id)
