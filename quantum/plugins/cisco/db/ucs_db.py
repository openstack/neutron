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

import quantum.db.api as db
import ucs_models


def get_all_ucsmbinding():
    """Lists all the ucsm bindings"""
    session = db.get_session()
    try:
        bindings = session.query(ucs_models.UcsmBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_ucsmbinding(ucsm_ip):
    """Lists a ucsm binding"""
    session = db.get_session()
    try:
        binding = session.query(ucs_models.UcsmBinding).\
          filter_by(ucsm_ip=ucsm_ip).\
          one()
        return binding
    except exc.NoResultFound:
        raise Exception("No binding found with ip = %s" % ucsm_ip)


def add_ucsmbinding(ucsm_ip, network_id):
    """Adds a ucsm binding"""
    session = db.get_session()
    try:
        ip = session.query(ucs_models.UcsmBinding).\
          filter_by(ucsm_ip=ucsm_ip).\
          one()
        raise Exception("Binding with ucsm ip \"%s\" already exists" % ucsm_ip)
    except exc.NoResultFound:
        binding = ucs_models.UcsmBinding(ucsm_ip, network_id)
        session.add(binding)
        session.flush()
        return binding


def remove_ucsmbinding(ucsm_ip):
    """Removes a ucsm binding"""
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
        raise Exception("No binding with ip = %s" % ucsm_ip)


def get_all_dynamicvnics():
    """Lists all the dynamic vnics"""
    session = db.get_session()
    try:
        vnics = session.query(ucs_models.DynamicVnic).\
          all()
        return vnics
    except exc.NoResultFound:
        return []


def get_dynamicvnic(vnic_id):
    """Lists a dynamic vnic"""
    session = db.get_session()
    try:
        vnic = session.query(ucs_models.DynamicVnic).\
          filter_by(uuid=vnic_id).\
          one()
        return vnic
    except exc.NoResultFound:
        raise Exception("No dynamic vnic found with id = %s" % vnic_id)


def add_dynamicvnic(device_name, blade_id):
    """Adds a dynamic vnic"""
    session = db.get_session()
    try:
        name = session.query(ucs_models.DynamicVnic).\
          filter_by(device_name=device_name).\
          one()
        raise Exception("Dynamic vnic with device name %s already exists" % \
                                                                device_name)
    except exc.NoResultFound:
        vnic = ucs_models.DynamicVnic(device_name, blade_id)
        session.add(vnic)
        session.flush()
        return vnic


def remove_dynamicvnic(vnic_id):
    """Removes a dynamic vnic"""
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


def update_dynamicvnic(vnic_id, new_device_name=None, new_blade_id=None):
    """Updates dynamic vnic"""
    session = db.get_session()
    try:
        vnic = session.query(ucs_models.DynamicVnic).\
          filter_by(uuid=vnic_id).\
          one()
        if new_device_name:
            vnic.device_name = new_device_name
        if new_blade_id:
            vnic.blade_id = new_blade_id
        session.merge(vnic)
        session.flush()
        return vnic
    except exc.NoResultFound:
        raise Exception("No dynamic vnic with id = %s" % vnic_id)


def get_all_blades():
    """Lists all the blades details"""
    session = db.get_session()
    try:
        blades = session.query(ucs_models.UcsBlade).\
          all()
        return blades
    except exc.NoResultFound:
        return []


def get_blade(blade_id):
    """Lists a blade details"""
    session = db.get_session()
    try:
        blade = session.query(ucs_models.UcsBlade).\
          filter_by(uuid=blade_id).\
          one()
        return blade
    except exc.NoResultFound:
        raise Exception("No blade found with id = %s" % blade_id)


def add_blade(mgmt_ip, mac_addr, chassis_id, ucsm_ip):
    """Adds a blade"""
    session = db.get_session()
    try:
        ip = session.query(ucs_models.UcsBlade).\
          filter_by(mgmt_ip=mgmt_ip).\
          one()
        raise Exception("Blade with ip \"%s\" already exists" % mgmt_ip)
    except exc.NoResultFound:
        blade = ucs_models.UcsBlade(mgmt_ip, mac_addr, chassis_id, ucsm_ip)
        session.add(blade)
        session.flush()
        return blade


def remove_blade(blade_id):
    """Removes a blade"""
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


def update_blade(blade_id, new_mgmt_ip=None, new_mac_addr=None, \
                         new_chassis_id=None, new_ucsm_ip=None):
    """Updates details of a blade"""
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
        session.merge(blade)
        session.flush()
        return blade
    except exc.NoResultFound:
        raise Exception("No blade with id = %s" % blade_id)


def get_all_portbindings():
    """Lists all the port bindings"""
    session = db.get_session()
    try:
        port_bindings = session.query(ucs_models.PortBinding).\
          all()
        return port_bindings
    except exc.NoResultFound:
        return []


def get_portbinding(port_id):
    """Lists a port binding"""
    session = db.get_session()
    try:
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
        return port_binding
    except exc.NoResultFound:
        raise Exception("No port binding found with port id = %s" % port_id)


def add_portbinding(port_id, dynamic_vnic_id, portprofile_name, \
                                        vlan_name, vlan_id, qos):
    """Adds a port binding"""
    session = db.get_session()
    try:
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
        raise Exception("Port Binding with portid %s already exists" % port_id)
    except exc.NoResultFound:
        port_binding = ucs_models.PortBinding(port_id, dynamic_vnic_id, \
                                     portprofile_name, vlan_name, vlan_id, qos)
        session.add(port_binding)
        session.flush()
        return port_binding


def remove_portbinding(port_id):
    """Removes a port binding"""
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


def update_portbinding(port_id, dynamic_vnic_id=None, portprofile_name=None, \
                       vlan_name=None, vlan_id=None, qos=None):
    """Updates port binding"""
    session = db.get_session()
    try:
        port_binding = session.query(ucs_models.PortBinding).\
          filter_by(port_id=port_id).\
          one()
        if dynamic_vnic_id:
            port_binding.dynamic_vnic_id = dynamic_vnic_id
        if portprofile_name:
            port_binding.portprofile_name = portprofile_name
        if vlan_name:
            port_binding.vlan_name = vlan_name
        if vlan_name:
            port_binding.vlan_id = vlan_id
        if qos:
            port_binding.qos = qos
        session.merge(port_binding)
        session.flush()
        return port_binding
    except exc.NoResultFound:
        raise Exception("No port binding with port id = %s" % port_id)
