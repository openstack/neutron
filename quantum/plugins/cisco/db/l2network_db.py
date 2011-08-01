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

from sqlalchemy.orm import exc

import l2network_models
import quantum.db.api as db
import quantum.db.models as models


def get_all_vlan_bindings():
    """Lists all the vlan to network associations"""
    session = db.get_session()
    try:
        bindings = session.query(l2network_models.VlanBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_vlan_binding(netid):
    """Lists the vlan given a network_id"""
    session = db.get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        return binding
    except exc.NoResultFound:
        raise Exception("No network found with net-id = %s" % network_id)


def add_vlan_binding(vlanid, vlanname, netid):
    """Adds a vlan to network association"""
    session = db.get_session()
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
    session = db.get_session()
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
    session = db.get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        if newvlanid:
            binding.vlan_id = newvlanid
        if newvlanname:
            binding.vlan_name = newvlanname
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise Exception("No vlan binding found with network_id = %s" % netid)


def get_all_portprofiles():
    """Lists all the port profiles"""
    session = db.get_session()
    try:
        pps = session.query(l2network_models.PortProfile).\
          all()
        return pps
    except exc.NoResultFound:
        return []


def get_portprofile(ppid):
    """Lists a port profile"""
    session = db.get_session()
    try:
        pp = session.query(l2network_models.PortProfile).\
          filter_by(uuid=ppid).\
          one()
        return pp
    except exc.NoResultFound:
        raise Exception("No portprofile found with id = %s" % ppid)


def add_portprofile(ppname, vlanid, qos):
    """Adds a port profile"""
    session = db.get_session()
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
    session = db.get_session()
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
    session = db.get_session()
    try:
        pp = session.query(l2network_models.PortProfile).\
          filter_by(uuid=ppid).\
          one()
        if newppname:
            pp.name = newppname
        if newvlanid:
            pp.vlan_id = newvlanid
        if newqos:
            pp.qos = newqos
        session.merge(pp)
        session.flush()
        return pp
    except exc.NoResultFound:
        raise Exception("No port profile with id = %s" % ppid)


def get_all_pp_bindings():
    """Lists all the port profiles"""
    session = db.get_session()
    try:
        bindings = session.query(l2network_models.PortProfileBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_pp_binding(ppid):
    """Lists a port profile binding"""
    session = db.get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        return binding
    except exc.NoResultFound:
        raise Exception("No portprofile binding found with id = %s" % ppid)


def add_pp_binding(tenantid, networkid, ppid, default):
    """Adds a port profile binding"""
    session = db.get_session()
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
    session = db.get_session()
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
    session = db.get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        if newtenantid:
            binding.tenant_id = newtenantid
        if newnetworkid:
            binding.network_id = newnetworkid
        if newdefault:
            binding.default = newdefault
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise Exception("No port profile binding with id = %s" % ppid)
