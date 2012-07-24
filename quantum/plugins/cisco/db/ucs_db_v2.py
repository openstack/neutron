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

from quantum.db import api as db

from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import ucs_models_v2 as ucs_models


def get_all_portbindings():
    """Lists all the port bindings"""
    LOG.debug("db get_all_portbindings() called")
    session = db.get_session()
    try:
        port_bindings = session.query(ucs_models.PortBinding).all()
        return port_bindings
    except exc.NoResultFound:
        return []


def get_portbinding(port_id):
    """Lists a port binding"""
    LOG.debug("get_portbinding() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(port_id=port_id).one())
        return port_binding
    except exc.NoResultFound:
        raise c_exc.PortVnicNotFound(port_id=port_id)


def add_portbinding(port_id, blade_intf_dn, portprofile_name,
                    vlan_name, vlan_id, qos):
    """Adds a port binding"""
    LOG.debug("add_portbinding() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(port_id=port_id).one())
        raise c_exc.PortVnicBindingAlreadyExists(port_id=port_id)
    except exc.NoResultFound:
        port_binding = ucs_models.PortBinding(port_id, blade_intf_dn,
                                              portprofile_name, vlan_name,
                                              vlan_id, qos)
        session.add(port_binding)
        session.flush()
        return port_binding


def remove_portbinding(port_id):
    """Removes a port binding"""
    LOG.debug("db remove_portbinding() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(port_id=port_id).one())
        session.delete(port_binding)
        session.flush()
        return port_binding
    except exc.NoResultFound:
        pass


def update_portbinding(port_id, blade_intf_dn=None, portprofile_name=None,
                       vlan_name=None, vlan_id=None, qos=None,
                       tenant_id=None, instance_id=None,
                       vif_id=None):
    """Updates port binding"""
    LOG.debug("db update_portbinding() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(port_id=port_id).one())
        if blade_intf_dn:
            port_binding.blade_intf_dn = blade_intf_dn
        if portprofile_name:
            port_binding.portprofile_name = portprofile_name
        if vlan_name:
            port_binding.vlan_name = vlan_name
        if vlan_name:
            port_binding.vlan_id = vlan_id
        if qos:
            port_binding.qos = qos
        if tenant_id:
            port_binding.tenant_id = tenant_id
        if instance_id:
            port_binding.instance_id = instance_id
        if vif_id:
            port_binding.vif_id = vif_id
        session.merge(port_binding)
        session.flush()
        return port_binding
    except exc.NoResultFound:
        raise c_exc.PortVnicNotFound(port_id=port_id)


def update_portbinding_instance_id(port_id, instance_id):
    """Updates port binding for the instance ID"""
    LOG.debug("db update_portbinding_instance_id() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(port_id=port_id).one())
        port_binding.instance_id = instance_id
        session.merge(port_binding)
        session.flush()
        return port_binding
    except exc.NoResultFound:
        raise c_exc.PortVnicNotFound(port_id=port_id)


def update_portbinding_vif_id(port_id, vif_id):
    """Updates port binding for the VIF ID"""
    LOG.debug("db update_portbinding_vif_id() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(port_id=port_id).one())
        port_binding.vif_id = vif_id
        session.merge(port_binding)
        session.flush()
        return port_binding
    except exc.NoResultFound:
        raise c_exc.PortVnicNotFound(port_id=port_id)


def get_portbinding_dn(blade_intf_dn):
    """Lists a port binding"""
    LOG.debug("get_portbinding_dn() called")
    session = db.get_session()
    try:
        port_binding = (session.query(ucs_models.PortBinding).
                        filter_by(blade_intf_dn=blade_intf_dn).one())
        return port_binding
    except exc.NoResultFound:
        return []
