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
#
# @author: Rohit Agarwalla, Cisco Systems, Inc.
# @author: Arvind Somya, Cisco Systems, Inc. (asomya@cisco.com)
#

from sqlalchemy.orm import exc

import quantum.db.api as db
from quantum.openstack.common import log as logging
from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import nexus_models_v2


LOG = logging.getLogger(__name__)


def get_all_nexusport_bindings():
    """Lists all the nexusport bindings"""
    LOG.debug(_("get_all_nexusport_bindings() called"))
    session = db.get_session()
    return session.query(nexus_models_v2.NexusPortBinding).all()


def get_nexusport_binding(port_id, vlan_id, switch_ip, instance_id):
    """Lists a nexusport binding"""
    LOG.debug(_("get_nexusport_binding() called"))
    session = db.get_session()
    return (session.query(nexus_models_v2.NexusPortBinding).
            filter_by(vlan_id=vlan_id).filter_by(switch_ip=switch_ip).
            filter_by(port_id=port_id).
            filter_by(instance_id=instance_id).all())


def get_nexusvlan_binding(vlan_id, switch_ip):
    """Lists a vlan and switch binding"""
    LOG.debug(_("get_nexusvlan_binding() called"))
    session = db.get_session()
    return (session.query(nexus_models_v2.NexusPortBinding).
            filter_by(vlan_id=vlan_id).filter_by(switch_ip=switch_ip).
            all())


def add_nexusport_binding(port_id, vlan_id, switch_ip, instance_id):
    """Adds a nexusport binding"""
    LOG.debug(_("add_nexusport_binding() called"))
    session = db.get_session()
    binding = nexus_models_v2.NexusPortBinding(
        port_id, vlan_id, switch_ip, instance_id)
    session.add(binding)
    session.flush()
    return binding


def remove_nexusport_binding(port_id, vlan_id, switch_ip, instance_id):
    """Removes a nexusport binding"""
    LOG.debug(_("remove_nexusport_binding() called"))
    session = db.get_session()
    binding = (session.query(nexus_models_v2.NexusPortBinding).
               filter_by(vlan_id=vlan_id).filter_by(switch_ip=switch_ip).
               filter_by(port_id=port_id).
               filter_by(instance_id=instance_id).all())

    for bind in binding:
        session.delete(bind)
    session.flush()
    return binding


def update_nexusport_binding(port_id, new_vlan_id):
    """Updates nexusport binding"""
    LOG.debug(_("update_nexusport_binding called"))
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


def get_nexusvm_binding(vlan_id, instance_id):
    """Lists nexusvm bindings"""
    LOG.debug(_("get_nexusvm_binding() called"))
    session = db.get_session()
    try:
        binding = (session.query(nexus_models_v2.NexusPortBinding).
                   filter_by(instance_id=instance_id).
                   filter_by(vlan_id=vlan_id).first())
        return binding
    except exc.NoResultFound:
        raise c_exc.NexusPortBindingNotFound(vlan_id=vlan_id)


def get_port_vlan_switch_binding(port_id, vlan_id, switch_ip):
    """Lists nexusvm bindings"""
    LOG.debug(_("get_port_vlan_switch_binding() called"))
    session = db.get_session()
    return (session.query(nexus_models_v2.NexusPortBinding).
            filter_by(port_id=port_id).filter_by(switch_ip=switch_ip).
            filter_by(vlan_id=vlan_id).all())


def get_port_switch_bindings(port_id, switch_ip):
    """List all vm/vlan bindings on a Nexus switch port."""
    LOG.debug(_("get_port_switch_bindings() called, "
                "port:'%(port_id)s', switch:'%(switch_ip)s'"),
              {'port_id': port_id, 'switch_ip': switch_ip})
    session = db.get_session()
    return (session.query(nexus_models_v2.NexusPortBinding).
            filter_by(port_id=port_id).
            filter_by(switch_ip=switch_ip).all())
