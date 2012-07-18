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

import logging as LOG

from sqlalchemy.orm import exc

import quantum.db.api as db

from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import nexus_models_v2


def get_all_nexusport_bindings():
    """Lists all the nexusport bindings"""
    LOG.debug("get_all_nexusport_bindings() called")
    session = db.get_session()
    try:
        bindings = session.query(nexus_models_v2.NexusPortBinding).all()
        return bindings
    except exc.NoResultFound:
        return []


def get_nexusport_binding(vlan_id):
    """Lists a nexusport binding"""
    LOG.debug("get_nexusport_binding() called")
    session = db.get_session()
    try:
        binding = (session.query(nexus_models_v2.NexusPortBinding).
                   filter_by(vlan_id=vlan_id).all())
        return binding
    except exc.NoResultFound:
        raise c_exc.NexusPortBindingNotFound(vlan_id=vlan_id)


def add_nexusport_binding(port_id, vlan_id):
    """Adds a nexusport binding"""
    LOG.debug("add_nexusport_binding() called")
    session = db.get_session()
    binding = nexus_models_v2.NexusPortBinding(port_id, vlan_id)
    session.add(binding)
    session.flush()
    return binding


def remove_nexusport_binding(vlan_id):
    """Removes a nexusport binding"""
    LOG.debug("remove_nexusport_binding() called")
    session = db.get_session()
    try:
        binding = (session.query(nexus_models_v2.NexusPortBinding).
                   filter_by(vlan_id=vlan_id).all())
        for bind in binding:
            session.delete(bind)
        session.flush()
        return binding
    except exc.NoResultFound:
        pass


def update_nexusport_binding(port_id, new_vlan_id):
    """Updates nexusport binding"""
    LOG.debug("update_nexusport_binding called")
    session = db.get_session()
    try:
        binding = (session.query(nexus_models_v2.NexusPortBinding).
                   filter_by(port_id=port_id).one())
        if new_vlan_id:
            binding["vlan_id"] = new_vlan_id
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise c_exc.NexusPortBindingNotFound()
