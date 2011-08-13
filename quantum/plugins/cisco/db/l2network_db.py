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

import ConfigParser
import os
import logging as LOG

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, exc, joinedload

from quantum.plugins.cisco import l2network_plugin_configuration as conf

import quantum.plugins.cisco.db.api as db

import l2network_models


CONF_FILE = "db_conn.ini"


def find_config(basepath):
    for root, dirs, files in os.walk(basepath):
        if CONF_FILE in files:
            return os.path.join(root, CONF_FILE)
    return None


def initialize(configfile=None):
    config = ConfigParser.ConfigParser()
    if configfile == None:
        if os.path.exists(CONF_FILE):
            configfile = CONF_FILE
        else:
            configfile = \
           find_config(os.path.abspath(os.path.dirname(__file__)))
    if configfile == None:
        raise Exception("Configuration file \"%s\" doesn't exist" %
              (configfile))
    LOG.debug("Using configuration file: %s" % configfile)
    config.read(configfile)

    DB_NAME = config.get("DATABASE", "name")
    DB_USER = config.get("DATABASE", "user")
    DB_PASS = config.get("DATABASE", "pass")
    DB_HOST = config.get("DATABASE", "host")
    options = {"sql_connection": "mysql://%s:%s@%s/%s" % (DB_USER,
    DB_PASS, DB_HOST, DB_NAME)}
    db.configure_db(options)


def create_vlanids():
    """Prepopulates the vlan_bindings table"""
    session = db.get_session()
    try:
        vlanid = session.query(l2network_models.VlanID).\
          all()
	pass
        #raise Exception("Vlan table not empty id for prepopulation")
    except exc.NoResultFound:
        start = int(conf.VLAN_START)
        end = int(conf.VLAN_END)
        while start <= end:
            vlanid = l2network_models.VlanID(start)
            session.add(vlanid)
            start += 1
        session.flush()
    return


def get_all_vlanids():
    session = db.get_session()
    try:
        vlanids = session.query(l2network_models.VlanID).\
          all()
        return vlanids
    except exc.NoResultFound:
        return []


def is_vlanid_used(vlan_id):
    session = db.get_session()
    try:
        vlanid = session.query(l2network_models.VlanID).\
          filter_by(vlan_id=vlan_id).\
          one()
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise Exception("No vlan found with vlan-id = %s" % vlan_id)


def release_vlanid(vlan_id):
    session = db.get_session()
    try:
        vlanid = session.query(l2network_models.VlanID).\
         filter_by(vlan_id=vlan_id).\
          one()
        vlanid["vlan_used"] = False
        session.merge(vlanid)
        session.flush()
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise Exception("Vlan id %s not present in table" % vlan_id)
    return


def delete_vlanid(vlan_id):
    session = db.get_session()
    try:
        vlanid = session.query(l2network_models.VlanID).\
          filter_by(vlan_id=vlan_id).\
          one()
        session.delete(vlanid)
        session.flush()
        return vlanid
    except exc.NoResultFound:
            pass


def reserve_vlanid():
    session = db.get_session()
    try:
        vlanids = session.query(l2network_models.VlanID).\
         filter_by(vlan_used=False).\
          all()
        rvlan = vlanids[0]
        rvlanid = session.query(l2network_models.VlanID).\
         filter_by(vlan_id=rvlan["vlan_id"]).\
          one()
        rvlanid["vlan_used"] = True
        session.merge(rvlanid)
        session.flush()
        return vlanids[0]["vlan_id"]
    except exc.NoResultFound:
        raise Exception("All vlan id's are used")


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
        return []	

def add_pp_binding(tenantid, portid, ppid, default):
    """Adds a port profile binding"""
    session = db.get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        raise Exception("Port profile binding with id \"%s\" already \
                                                         exists" % ppid)
    except exc.NoResultFound:
        binding = l2network_models.PortProfileBinding(tenantid, portid, \
                                                            ppid, default)
        session.add(binding)
        session.flush()
        return binding


def remove_pp_binding(portid, ppid):
    """Removes a port profile binding"""
    session = db.get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          filter_by(port_id=portid).\
          one()
        session.delete(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
            pass


def update_pp_binding(ppid, newtenantid=None, newportid=None, \
                                                    newdefault=None):
    """Updates port profile binding"""
    session = db.get_session()
    try:
        binding = session.query(l2network_models.PortProfileBinding).\
          filter_by(portprofile_id=ppid).\
          one()
        if newtenantid:
            binding["tenant_id"] = newtenantid
        if newportid:
            binding["port_id"] = newportid
        if newdefault:
            binding["default"] = newdefault
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise Exception("No port profile binding with id = %s" % ppid)
