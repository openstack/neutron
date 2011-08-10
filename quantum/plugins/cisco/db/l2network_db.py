# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Cisco Systems, Inc.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, exc, joinedload

import l2network_models


from quantum.common import exceptions as q_exc


_ENGINE = None
_MAKER = None
BASE = l2network_models.BASE


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


def _check_duplicate_net_name(tenant_id, net_name):
    session = get_session()
    try:
        net = session.query(l2network_models.Network).\
          filter_by(tenant_id=tenant_id, name=net_name).\
          one()
        raise q_exc.NetworkNameExists(tenant_id=tenant_id,
                        net_name=net_name, net_id=net.uuid)
    except exc.NoResultFound:
        # this is the "normal" path, as API spec specifies
        # that net-names are unique within a tenant
        pass


def network_create(tenant_id, name):
    session = get_session()

    _check_duplicate_net_name(tenant_id, name)
    with session.begin():
        net = l2network_models.Network(tenant_id, name)
        session.add(net)
        session.flush()
        return net


def network_list(tenant_id):
    session = get_session()
    return session.query(l2network_models.Network).\
      options(joinedload(l2network_models.Network.ports)). \
      filter_by(tenant_id=tenant_id).\
      all()


def network_get(net_id):
    session = get_session()
    try:
        return  session.query(l2network_models.Network).\
            filter_by(uuid=net_id).\
            one()
    except exc.NoResultFound, e:
        raise q_exc.NetworkNotFound(net_id=net_id)


def network_rename(net_id, tenant_id, new_name):
    session = get_session()
    net = network_get(net_id)
    _check_duplicate_net_name(tenant_id, new_name)
    net.name = new_name
    session.merge(net)
    session.flush()
    return net


def network_destroy(net_id):
    session = get_session()
    try:
        net = session.query(l2network_models.Network).\
          filter_by(uuid=net_id).\
          one()
        session.delete(net)
        session.flush()
        return net
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=net_id)


def port_create(net_id, state=None):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    with session.begin():
        port = l2network_models.Port(net_id)
        port['state'] = state or 'DOWN'
        session.add(port)
        session.flush()
        return port


def port_list(net_id):
    session = get_session()
    return session.query(l2network_models.Port).\
      options(joinedload(l2network_models.Port.network)). \
      filter_by(network_id=net_id).\
      all()


def port_get(port_id, net_id):
    # confirm network exists
    network_get(net_id)
    session = get_session()
    try:
        return  session.query(l2network_models.Port).\
          filter_by(uuid=port_id).\
          filter_by(network_id=net_id).\
          one()
    except exc.NoResultFound:
        raise q_exc.PortNotFound(net_id=net_id, port_id=port_id)


def port_set_state(port_id, net_id, new_state):
    if new_state not in ('ACTIVE', 'DOWN'):
        raise q_exc.StateInvalid(port_state=new_state)

    # confirm network exists
    network_get(net_id)

    port = port_get(port_id, net_id)
    session = get_session()
    port.state = new_state
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
            port = session.query(l2network_models.Port).\
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
    port = port_get(port_id, net_id)
    port.interface_id = None
    session.merge(port)
    session.flush()


def port_destroy(port_id, net_id):
    # confirm network exists
    network_get(net_id)

    session = get_session()
    try:
        port = session.query(l2network_models.Port).\
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


def get_all_vlan_bindings():
    """Lists all the vlan to network associations"""
    session = get_session()
    try:
        bindings = session.query(l2network_models.VlanBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_vlan_binding(netid):
    """Lists the vlan given a network_id"""
    session = get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        return binding
    except exc.NoResultFound:
        raise Exception("No network found with net-id = %s" % network_id)


def add_vlan_binding(vlanid, vlanname, netid):
    """Adds a vlan to network association"""
    session = get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(vlan_id=vlanid).\
          one()
        raise Exception("Vlan with id \"%s\" already exists" % vlanid)
    except exc.NoResultFound:
        binding = l2network_models.VlanBinding(vlanid, vlanname, netid)
        session.add(binding)
        session.flush()
        return binding


def remove_vlan_binding(netid):
    """Removes a vlan to network association"""
    session = get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        session.delete(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
            pass


def update_vlan_binding(netid, newvlanid=None, newvlanname=None):
    """Updates a vlan to network association"""
    session = get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        if newvlanid:
            binding["vlan_id"] = newvlanid
        if newvlanname:
            binding["vlan_name"] = newvlanname
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise Exception("No vlan binding found with network_id = %s" % netid)


def get_all_portprofiles():
    """Lists all the port profiles"""
    session = get_session()
    try:
        pps = session.query(l2network_models.PortProfile).\
          all()
        return pps
    except exc.NoResultFound:
        return []


def get_portprofile(ppid):
    """Lists a port profile"""
    session = get_session()
    try:
        pp = session.query(l2network_models.PortProfile).\
          filter_by(uuid=ppid).\
          one()
        return pp
    except exc.NoResultFound:
        raise Exception("No portprofile found with id = %s" % ppid)


def add_portprofile(ppname, vlanid, qos):
    """Adds a port profile"""
    session = get_session()
    try:
        pp = session.query(l2network_models.PortProfile).\
          filter_by(name=ppname).\
          one()
        raise Exception("Port profile with name %s already exists" % ppname)
    except exc.NoResultFound:
        pp = l2network_models.PortProfile(ppname, vlanid, qos)
        session.add(pp)
        session.flush()
        return pp


def remove_portprofile(ppid):
    """Removes a port profile"""
    session = get_session()
    try:
        pp = session.query(l2network_models.PortProfile).\
          filter_by(uuid=ppid).\
          one()
        session.delete(pp)
        session.flush()
        return pp
    except exc.NoResultFound:
            pass


def update_portprofile(ppid, newppname=None, newvlanid=None, newqos=None):
    """Updates port profile"""
    session = get_session()
    try:
        pp = session.query(l2network_models.PortProfile).\
          filter_by(uuid=ppid).\
          one()
        if newppname:
            pp["name"] = newppname
        if newvlanid:
            pp["vlan_id"] = newvlanid
        if newqos:
            pp["qos"] = newqos
        session.merge(pp)
        session.flush()
        return pp
    except exc.NoResultFound:
        raise Exception("No port profile with id = %s" % ppid)


def get_all_pp_bindings():
    """Lists all the port profiles"""
    session = get_session()
    try:
        bindings = session.query(l2network_models.PortProfileBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_pp_binding(ppid):
    """Lists a port profile binding"""
    session = get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        return binding
    except exc.NoResultFound:
        raise Exception("No portprofile binding found with id = %s" % ppid)


def add_pp_binding(tenantid, networkid, ppid, default):
    """Adds a port profile binding"""
    session = get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        raise Exception("Port profile binding with id \"%s\" already \
                                                         exists" % ppid)
    except exc.NoResultFound:
        binding = l2network_models.PortProfileBinding(tenantid, networkid, \
                                                            ppid, default)
        session.add(binding)
        session.flush()
        return binding


def remove_pp_binding(ppid):
    """Removes a port profile binding"""
    session = get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        session.delete(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
            pass


def update_pp_binding(ppid, newtenantid=None, newnetworkid=None, \
                                                    newdefault=None):
    """Updates port profile binding"""
    session = get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        if newtenantid:
            binding["tenant_id"] = newtenantid
        if newnetworkid:
            binding["network_id"] = newnetworkid
        if newdefault:
            binding["default"] = newdefault
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise Exception("No port profile binding with id = %s" % ppid)
