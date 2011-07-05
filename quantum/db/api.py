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

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, exc

from quantum.db import models

_ENGINE = None
_MAKER = None
BASE = models.BASE


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


def network_create(tenant_id, name):
    session = get_session()
    net = None
    try:
        net = session.query(models.Network).\
          filter_by(tenant_id=tenant_id, name=name).\
          one()
        raise Exception("Network with name %(name)s already " \
                        "exists for tenant %(tenant_id)s" % locals())
    except exc.NoResultFound:
        with session.begin():
            net = models.Network(tenant_id, name)
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
    except exc.NoResultFound:
        raise Exception("No net found with id = %s" % net_id)


def network_rename(net_id, tenant_id, new_name):
    session = get_session()
    try:
        res = session.query(models.Network).\
          filter_by(tenant_id=tenant_id, name=new_name).\
          one()
    except exc.NoResultFound:
        net = network_get(net_id)
        net.name = new_name
        session.merge(net)
        session.flush()
        return net
    raise Exception("A network with name \"%s\" already exists" % new_name)


def network_destroy(net_id):
    session = get_session()
    try:
        net = session.query(models.Network).\
          filter_by(uuid=net_id).\
          one()
        session.delete(net)
        session.flush()
        return net
    except exc.NoResultFound:
        raise Exception("No network found with id = %s" % net_id)


def port_create(net_id):
    session = get_session()
    with session.begin():
        port = models.Port(net_id)
        session.add(port)
        session.flush()
        return port


def port_list(net_id):
    session = get_session()
    return session.query(models.Port).\
      filter_by(network_id=net_id).\
      all()


def port_get(port_id):
    session = get_session()
    try:
        return  session.query(models.Port).\
          filter_by(uuid=port_id).\
          one()
    except exc.NoResultFound:
        raise Exception("No port found with id = %s " % port_id)


def port_set_state(port_id, new_state):
    port = port_get(port_id)
    if port:
        session = get_session()
        port.state = new_state
        session.merge(port)
        session.flush()
        return port


def port_set_attachment(port_id, new_interface_id):
    session = get_session()
    ports = []
    if new_interface_id != "":
        try:
            ports = session.query(models.Port).\
            filter_by(interface_id=new_interface_id).\
            all()
        except exc.NoResultFound:
            pass
    if len(ports) == 0:
        port = port_get(port_id)
        port.interface_id = new_interface_id
        session.merge(port)
        session.flush()
        return port
    else:
        raise Exception("Port with attachment \"%s\" already exists"
                        % (new_interface_id))


def port_destroy(port_id):
    session = get_session()
    try:
        port = session.query(models.Port).\
            filter_by(uuid=port_id).\
            one()
        session.delete(port)
        session.flush()
        return port
    except exc.NoResultFound:
        raise Exception("No port found with id = %s " % port_id)
