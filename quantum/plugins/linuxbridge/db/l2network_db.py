# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Cisco Systems, Inc.
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

from sqlalchemy import func
from sqlalchemy.orm import exc

from quantum.common import exceptions as q_exc
from quantum.plugins.linuxbridge import plugin_configuration as conf
from quantum.plugins.linuxbridge.common import exceptions as c_exc
from quantum.plugins.linuxbridge.db import l2network_models

import logging

import quantum.db.api as db


LOG = logging.getLogger(__name__)


def initialize():
    'Establish database connection and load models'
    if conf.DB_CONNECTION == 'sqlite':
        options = {"sql_connection": "sqlite://"}
    else:
        options = {"sql_connection": "mysql://%s:%s@%s:%s/%s" % (conf.DB_USER,
                                                                 conf.DB_PASS,
                                                                 conf.DB_HOST,
                                                                 conf.DB_PORT,
                                                                 conf.DB_NAME)}

    db.configure_db(options)
    create_vlanids()


def create_vlanids():
    """Prepopulates the vlan_bindings table"""
    LOG.debug("create_vlanids() called")
    session = db.get_session()
    start = int(conf.VLAN_START)
    end = int(conf.VLAN_END)
    try:
        vlanid = session.query(l2network_models.VlanID).\
          one()
    except exc.MultipleResultsFound:
        """
        TODO (Sumit): Salvatore rightly points out that this will not handle
        change in VLAN ID range across server reboots. This is currently not
        a supported feature. This logic will need to change if this feature
        has to be supported.
        Per Dan's suggestion we just throw a server exception for now.
        """
        current_start = \
                int(session.query(func.min(l2network_models.VlanID.vlan_id)).
                    one()[0])
        current_end = \
                int(session.query(func.max(l2network_models.VlanID.vlan_id)).
                    one()[0])
        if current_start != start or current_end != end:
            LOG.debug("Old VLAN range %s-%s" % (current_start, current_end))
            LOG.debug("New VLAN range %s-%s" % (start, end))
            raise c_exc.UnableToChangeVlanRange(range_start=current_start,
                                                range_end=current_end)
    except exc.NoResultFound:
        LOG.debug("Setting VLAN range to %s-%s" % (start, end))
        while start <= end:
            vlanid = l2network_models.VlanID(start)
            session.add(vlanid)
            start += 1
        session.flush()
    return


def get_all_vlanids():
    """Gets all the vlanids"""
    LOG.debug("get_all_vlanids() called")
    session = db.get_session()
    try:
        vlanids = session.query(l2network_models.VlanID).\
          all()
        return vlanids
    except exc.NoResultFound:
        return []


def is_vlanid_used(vlan_id):
    """Checks if a vlanid is in use"""
    LOG.debug("is_vlanid_used() called")
    session = db.get_session()
    try:
        vlanid = session.query(l2network_models.VlanID).\
          filter_by(vlan_id=vlan_id).\
          one()
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def release_vlanid(vlan_id):
    """Sets the vlanid state to be unused"""
    LOG.debug("release_vlanid() called")
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
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)
    return


def delete_vlanid(vlan_id):
    """Deletes a vlanid entry from db"""
    LOG.debug("delete_vlanid() called")
    session = db.get_session()
    try:
        vlanid = session.query(l2network_models.VlanID).\
          filter_by(vlan_id=vlan_id).\
          one()
        session.delete(vlanid)
        session.flush()
        return vlanid
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def reserve_vlanid():
    """Reserves the first unused vlanid"""
    LOG.debug("reserve_vlanid() called")
    session = db.get_session()
    try:
        rvlan = session.query(l2network_models.VlanID).\
          first()
        if not rvlan:
            create_vlanids()

        rvlan = session.query(l2network_models.VlanID).\
         filter_by(vlan_used=False).\
          first()
        if not rvlan:
            raise c_exc.VlanIDNotAvailable()

        rvlanid = session.query(l2network_models.VlanID).\
         filter_by(vlan_id=rvlan["vlan_id"]).\
          one()
        rvlanid["vlan_used"] = True
        session.merge(rvlanid)
        session.flush()
        return rvlan["vlan_id"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotAvailable()


def get_all_vlanids_used():
    """Gets all the vlanids used"""
    LOG.debug("get_all_vlanids() called")
    session = db.get_session()
    try:
        vlanids = session.query(l2network_models.VlanID).\
        filter_by(vlan_used=True).\
          all()
        return vlanids
    except exc.NoResultFound:
        return []


def get_all_vlan_bindings():
    """Lists all the vlan to network associations"""
    LOG.debug("get_all_vlan_bindings() called")
    session = db.get_session()
    try:
        bindings = session.query(l2network_models.VlanBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_vlan_binding(netid):
    """Lists the vlan given a network_id"""
    LOG.debug("get_vlan_binding() called")
    session = db.get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        return binding
    except exc.NoResultFound:
        raise c_exc.NetworkVlanBindingNotFound(network_id=netid)


def add_vlan_binding(vlanid, netid):
    """Adds a vlan to network association"""
    LOG.debug("add_vlan_binding() called")
    session = db.get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(vlan_id=vlanid).\
          one()
        raise c_exc.NetworkVlanBindingAlreadyExists(vlan_id=vlanid,
                                                    network_id=netid)
    except exc.NoResultFound:
        binding = l2network_models.VlanBinding(vlanid, netid)
        session.add(binding)
        session.flush()
        return binding


def remove_vlan_binding(netid):
    """Removes a vlan to network association"""
    LOG.debug("remove_vlan_binding() called")
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


def update_vlan_binding(netid, newvlanid=None):
    """Updates a vlan to network association"""
    LOG.debug("update_vlan_binding() called")
    session = db.get_session()
    try:
        binding = session.query(l2network_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        if newvlanid:
            binding["vlan_id"] = newvlanid
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=netid)
