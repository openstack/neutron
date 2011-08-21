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

import logging as LOG

from sqlalchemy.orm import exc

import quantum.plugins.cisco.db.api as db
import ucs_models

from quantum.plugins.cisco.common import cisco_exceptions as c_exc


def get_all_ucsmbinding():
    """Lists all the ucsm bindings"""
    LOG.debug("get_all_ucsmbinding()  called")
    session = db.get_session()
    try:
        bindings = session.query(ucs_models.UcsmBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_ucsmbinding(ucsm_ip):
    """Lists a ucsm binding"""
    LOG.debug("get_ucsmbinding() called")
    session = db.get_session()
    try:
        binding = session.query(ucs_models.UcsmBinding).\
          filter_by(ucsm_ip=ucsm_ip).\
          one()
        return binding
    except exc.NoResultFound:
        raise c_exc.UcsmBindingNotFound(ucsm_ip=ucsm_ip)


def add_ucsmbinding(ucsm_ip, network_id):
    """Adds a ucsm binding"""
    LOG.debug("add_ucsmbinding() called")
    session = db.get_session()
    try:
        binding = session.query(ucs_models.UcsmBinding).\
          filter_by(ucsm_ip=ucsm_ip).\
          one()
        raise c_exc.UcsmBindingAlreadyExists(ucsm_ip=ucsm_ip)
    except exc.NoResultFound:
        binding = ucs_models.UcsmBinding(ucsm_ip, network_id)
        session.add(binding)
        session.flush()
        return binding


def remove_ucsmbinding(ucsm_ip):
    """Removes a ucsm binding"""
    LOG.debug("remove_ucsmbinding() called")
    session = db.get_session()
    try:
        binding = session.query(ucs_models.UcsmBinding).\
          filter_by(ucsm_ip=ucsm_ip).\
          one()
        session.delete(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        pass


def update_ucsmbinding(ucsm_ip, new_network_id):
    """Updates ucsm binding"""
    LOG.debug("update_ucsmbinding() called")
    session = db.get_session()
    try:
        binding = session.query(ucs_models.UcsmBinding).\
          filter_by(ucsm_ip=ucsm_ip).\
          one()
        if new_network_id:
            binding.network_id = new_network_id
        session.merge(binding)
        session.flush()
        return binding
    except exc.NoResultFound:
        raise c_exc.UcsmBindingNotFound(ucsm_ip=ucsm_ip)


def get_all_dynamicvnics():
    """Lists all the dynamic vnics"""
    LOG.debug("get_all_dynamicvnics() called")
    session = db.get_session()
    try:
        vnics = session.query(ucs_models.DynamicVnic).\
          all()
        return vnics
    except exc.NoResultFound:
        return []


def get_dynamicvnic(vnic_id):
    """Lists a dynamic vnic"""
    LOG.debug("get_dynamicvnic() called")
    session = db.get_session()
    try:
        vnic = session.query(ucs_models.DynamicVnic).\
          filter_by(uuid=vnic_id).\
          one()
        return vnic
    except exc.NoResultFound:
        raise c_exc.DynamicVnicNotFound(vnic_id=vnic_id)


def add_dynamicvnic(device_name, blade_id, vnic_state):
    """Adds a dynamic vnic"""
    LOG.debug("add_dynamicvnic() called")
    session = db.get_session()
    try:
        vnic = session.query(ucs_models.DynamicVnic).\
          filter_by(device_name=device_name).\
          one()
        raise c_exc.DynamicVnicAlreadyExists(device_name=device_name)
    except exc.NoResultFound:
        vnic = ucs_models.DynamicVnic(device_name, blade_id, vnic_state)
        session.add(vnic)
        session.flush()
        return vnic


def remove_dynamicvnic(vnic_id):
    """Removes a dynamic vnic"""
    LOG.debug("remove_dynamicvnic() called")
    session = db.get_session()
    try:
        vnic = session.query(ucs_models.DynamicVnic).\
          filter_by(uuid=vnic_id).\
          one()
        session.delete(vnic)
        session.flush()
        return vnic
    except exc.NoResultFound:
        pass


def update_dynamicvnic(vnic_id, new_device_name=None, new_blade_id=None,
                       vnic_state=None, blade_intf_dn=None,
                       blade_intf_order=None, blade_int_link_state=None,
                       blade_intf_oper_state=None, blade_intf_inst_type=None,
                       blade_intf_reservation=None):
    """Updates dynamic vnic"""
    LOG.debug("update_dynamicvnic() called")
    session = db.get_session()
    try:
        vnic = session.query(ucs_models.DynamicVnic).\
          filter_by(uuid=vnic_id).\
          one()
        if new_device_name:
            vnic.device_name = new_device_name
        if new_blade_id:
            vnic.blade_id = new_blade_id
        if vnic_state:
            vnic.vnic_state = vnic_state
        if blade_intf_dn:
            vnic.blade_intf_dn = blade_intf_dn
        if blade_intf_order:
            vnic.blade_intf_order = blade_intf_order
        if blade_int_link_state:
            vnic.blade_int_link_state = blade_int_link_state
        if blade_intf_oper_state:
            vnic.blade_intf_oper_state = blade_intf_oper_state
        if blade_intf_inst_type:
            vnic.blade_intf_inst_type = blade_intf_inst_type
        if blade_intf_reservation:
            vnic.blade_intf_reservation = blade_intf_reservation
        session.merge(vnic)
        session.flush()
        return vnic
    except exc.NoResultFound:
        raise c_exc.DynamicVnicNotFound(vnic_id=vnic_id)


def get_all_blades():
    """Lists all the blades details"""
    LOG.debug("get_all_blades() called")
    session = db.get_session()
    try:
        blades = session.query(ucs_models.UcsBlade).\
          all()
        return blades
    except exc.NoResultFound:
        return []


def get_blade(blade_id):
    """Lists a blade details"""
    LOG.debug("get_blade() called")
    session = db.get_session()
    try:
        blade = session.query(ucs_models.UcsBlade).\
          filter_by(uuid=blade_id).\
          one()
        return blade
    except exc.NoResultFound:
        raise c_exc.BladeNotFound(blade_id=blade_id)


def add_blade(mgmt_ip, mac_addr, chassis_id, ucsm_ip, blade_state,
              vnics_used, hostname):
    """Adds a blade"""
    LOG.debug("add_blade() called")
    session = db.get_session()
    try:
        blade = session.query(ucs_models.UcsBlade).\
          filter_by(mgmt_ip=mgmt_ip).\
          one()
        raise c_exc.BladeAlreadyExists(mgmt_ip=mgmt_ip)
    except exc.NoResultFound:
        blade = ucs_models.UcsBlade(mgmt_ip, mac_addr, chassis_id, ucsm_ip,
                                    blade_state, vnics_used, hostname)
        session.add(blade)
        session.flush()
        return blade


def remove_blade(blade_id):
    """Removes a blade"""
    LOG.debug("remove_blade() called")
    session = db.get_session()
    try:
        blade = session.query(ucs_models.UcsBlade).\
          filter_by(uuid=blade_id).\
          one()
        session.delete(blade)
        session.flush()
        return blade
    except exc.NoResultFound:
        pass


def update_blade(blade_id, new_mgmt_ip=None, new_mac_addr=None,
                         new_chassis_id=None, new_ucsm_ip=None,
                         new_blade_state=None, new_vnics_used=None,
                         new_hostname=None):
    """Updates details of a blade"""
    LOG.debug("update_blade() called")
    session = db.get_session()
    try:
        blade = session.query(ucs_models.UcsBlade).\
          filter_by(uuid=blade_id).\
          one()
        if new_mgmt_ip:
            blade.mgmt_ip = new_mgmt_ip
        if new_mac_addr:
            blade.mac_addr = new_mac_addr
        if new_chassis_id:
            blade.chassis_id = new_chassis_id
        if new_ucsm_ip:
            blade.ucsm_ip = new_ucsm_ip
        if new_blade_state:
            blade.blade_state = new_blade_state
        if new_vnics_used:
            blade.vnics_used = new_vnics_used
        if new_hostname:
            blade.hostname = new_hostname
        session.merge(blade)
        session.flush()
        return blade
    except exc.NoResultFound:
        raise c_exc.BladeNotFound(blade_id=blade_id)


def get_all_portbindings():
    """Lists all the port bindings"""
    LOG.debug("db get_all_portbindings() called")
    session = db.get_session()
    try:
        port_bindings = session.query(ucs_models.PortBinding).\
          all()
        return port_bindings
    except exc.NoResultFound:
        return []


def get_portbinding(port_id):
    """Lists a port binding"""
    LOG.debug("get_portbinding() called")
    session = db.get_session()
    try:
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
        return port_binding
    except exc.NoResultFound:
        raise c_exc.PortVnicNotFound(port_id=port_id)


def add_portbinding(port_id, blade_intf_dn, portprofile_name,
                                        vlan_name, vlan_id, qos):
    """Adds a port binding"""
    LOG.debug("add_portbinding() called")
    session = db.get_session()
    try:
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
        raise c_exc.PortVnicBindingAlreadyExists(port_id=port_id)
    except exc.NoResultFound:
        port_binding = ucs_models.PortBinding(port_id, blade_intf_dn, \
                                    portprofile_name, vlan_name, vlan_id, qos)
        session.add(port_binding)
        session.flush()
        return port_binding


def remove_portbinding(port_id):
    """Removes a port binding"""
    LOG.debug("db remove_portbinding() called")
    session = db.get_session()
    try:
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
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
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
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
