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

import logging

from sqlalchemy import func
from sqlalchemy.orm import exc

from quantum.common import exceptions as q_exc
import quantum.db.api as db
from quantum.openstack.common import cfg
from quantum.plugins.linuxbridge.common import config
from quantum.plugins.linuxbridge.common import exceptions as c_exc
from quantum.plugins.linuxbridge.db import l2network_models
from quantum.plugins.linuxbridge.db import l2network_models_v2

LOG = logging.getLogger(__name__)

# The global variable for the database version model
L2_MODEL = l2network_models


def initialize(base=None):
    global L2_MODEL
    options = {"sql_connection": "%s" % cfg.CONF.DATABASE.sql_connection}
    options.update({"sql_max_retries": cfg.CONF.DATABASE.sql_max_retries})
    options.update({"reconnect_interval":
                   cfg.CONF.DATABASE.reconnect_interval})
    if base:
        options.update({"base": base})
        L2_MODEL = l2network_models_v2
    db.configure_db(options)
    create_vlanids()


def create_vlanids():
    """Prepopulate the vlan_bindings table"""
    LOG.debug("create_vlanids() called")
    session = db.get_session()
    start = cfg.CONF.VLANS.vlan_start
    end = cfg.CONF.VLANS.vlan_end
    try:
        vlanid = session.query(L2_MODEL.VlanID).one()
    except exc.MultipleResultsFound:
        """
        TODO (Sumit): Salvatore rightly points out that this will not handle
        change in VLAN ID range across server reboots. This is currently not
        a supported feature. This logic will need to change if this feature
        has to be supported.
        Per Dan's suggestion we just throw a server exception for now.
        """
        current_start = (
            int(session.query(func.min(L2_MODEL.VlanID.vlan_id)).
                one()[0]))
        current_end = (
            int(session.query(func.max(L2_MODEL.VlanID.vlan_id)).
                one()[0]))
        if current_start != start or current_end != end:
            LOG.debug("Old VLAN range %s-%s" % (current_start, current_end))
            LOG.debug("New VLAN range %s-%s" % (start, end))
            raise c_exc.UnableToChangeVlanRange(range_start=current_start,
                                                range_end=current_end)
    except exc.NoResultFound:
        LOG.debug("Setting VLAN range to %s-%s" % (start, end))
        while start <= end:
            vlanid = L2_MODEL.VlanID(start)
            session.add(vlanid)
            start += 1
        session.flush()
    return


def get_all_vlanids():
    """Get all the vlanids"""
    LOG.debug("get_all_vlanids() called")
    session = db.get_session()
    try:
        vlanids = (session.query(L2_MODEL.VlanID).
                   all())
        return vlanids
    except exc.NoResultFound:
        return []


def is_vlanid_used(vlan_id):
    """Check if a vlanid is in use"""
    LOG.debug("is_vlanid_used() called")
    session = db.get_session()
    try:
        vlanid = (session.query(L2_MODEL.VlanID).
                  filter_by(vlan_id=vlan_id).
                  one())
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def release_vlanid(vlan_id):
    """Set the vlanid state to be unused, and delete if not in range"""
    LOG.debug("release_vlanid() called")
    session = db.get_session()
    try:
        vlanid = (session.query(L2_MODEL.VlanID).
                  filter_by(vlan_id=vlan_id).
                  one())
        vlanid["vlan_used"] = False
        if (vlan_id >= cfg.CONF.VLANS.vlan_start and
            vlan_id <= cfg.CONF.VLANS.vlan_end):
            session.merge(vlanid)
        else:
            session.delete(vlanid)
        session.flush()
        return vlanid["vlan_used"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)
    return


def delete_vlanid(vlan_id):
    """Delete a vlanid entry from db"""
    LOG.debug("delete_vlanid() called")
    session = db.get_session()
    try:
        vlanid = (session.query(L2_MODEL.VlanID).
                  filter_by(vlan_id=vlan_id).
                  one())
        session.delete(vlanid)
        session.flush()
        return vlanid
    except exc.NoResultFound:
        raise c_exc.VlanIDNotFound(vlan_id=vlan_id)


def reserve_vlanid():
    """Reserve the first unused vlanid"""
    LOG.debug("reserve_vlanid() called")
    session = db.get_session()
    try:
        rvlan = (session.query(L2_MODEL.VlanID).
                 first())
        if not rvlan:
            create_vlanids()

        rvlan = (session.query(L2_MODEL.VlanID).
                 filter_by(vlan_used=False).
                 first())
        if not rvlan:
            raise c_exc.VlanIDNotAvailable()

        rvlanid = (session.query(L2_MODEL.VlanID).
                   filter_by(vlan_id=rvlan["vlan_id"]).
                   one())
        rvlanid["vlan_used"] = True
        session.merge(rvlanid)
        session.flush()
        return rvlan["vlan_id"]
    except exc.NoResultFound:
        raise c_exc.VlanIDNotAvailable()


def reserve_specific_vlanid(vlan_id, net_id):
    """Reserve a specific vlanid"""
    LOG.debug("reserve_specific_vlanid() called")
    if vlan_id < 1 or vlan_id > 4094:
        msg = _("Specified VLAN %s outside legal range (1-4094)") % vlan_id
        raise q_exc.InvalidInput(error_message=msg)
    session = db.get_session()
    try:
        rvlanid = (session.query(l2network_models.VlanID).
                   filter_by(vlan_id=vlan_id).
                   one())
        if rvlanid["vlan_used"]:
            raise q_exc.VlanIdInUse(net_id=net_id, vlan_id=vlan_id)
        LOG.debug("reserving dynamic vlanid %s" % vlan_id)
        rvlanid["vlan_used"] = True
        session.merge(rvlanid)
    except exc.NoResultFound:
        rvlanid = l2network_models.VlanID(vlan_id)
        LOG.debug("reserving non-dynamic vlanid %s" % vlan_id)
        rvlanid["vlan_used"] = True
        session.add(rvlanid)
    session.flush()


def get_all_vlanids_used():
    """Get all the vlanids used"""
    LOG.debug("get_all_vlanids() called")
    session = db.get_session()
    try:
        vlanids = (session.query(L2_MODEL.VlanID).
                   filter_by(vlan_used=True).
                   all())
        return vlanids
    except exc.NoResultFound:
        return []


def get_all_vlan_bindings():
    """List all the vlan to network associations"""
    LOG.debug("get_all_vlan_bindings() called")
    session = db.get_session()
    try:
        bindings = (session.query(L2_MODEL.VlanBinding).
                    all())
        return bindings
    except exc.NoResultFound:
        return []


def get_vlan_binding(netid):
    """List the vlan given a network_id"""
    LOG.debug("get_vlan_binding() called")
    session = db.get_session()
    try:
        binding = (session.query(L2_MODEL.VlanBinding).
                   filter_by(network_id=netid).
                   one())
        return binding
    except exc.NoResultFound:
        raise c_exc.NetworkVlanBindingNotFound(network_id=netid)


def add_vlan_binding(vlanid, netid):
    """Add a vlan to network association"""
    LOG.debug("add_vlan_binding() called")
    session = db.get_session()
    try:
        binding = (session.query(L2_MODEL.VlanBinding).
                   filter_by(vlan_id=vlanid).
                   one())
        raise c_exc.NetworkVlanBindingAlreadyExists(vlan_id=vlanid,
                                                    network_id=netid)
    except exc.NoResultFound:
        binding = L2_MODEL.VlanBinding(vlanid, netid)
        session.add(binding)
        session.flush()
        return binding


def remove_vlan_binding(netid):
    """Remove a vlan to network association"""
    LOG.debug("remove_vlan_binding() called")
    session = db.get_session()
    try:
        binding = (session.query(L2_MODEL.VlanBinding).
                   filter_by(network_id=netid).
                   one())
        session.delete(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        pass


def update_vlan_binding(netid, newvlanid=None):
    """Update a vlan to network association"""
    LOG.debug("update_vlan_binding() called")
    session = db.get_session()
    try:
        binding = (session.query(L2_MODEL.VlanBinding).
                   filter_by(network_id=netid).
                   one())
        if newvlanid:
            binding["vlan_id"] = newvlanid
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise q_exc.NetworkNotFound(net_id=netid)
