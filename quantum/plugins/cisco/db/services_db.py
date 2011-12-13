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
#
# @author: Edgar Magana, Cisco Systems, Inc.

import logging as LOG

from sqlalchemy.orm import exc

import quantum.plugins.cisco.db.api as db

from quantum.plugins.cisco.common import cisco_exceptions as c_exc
from quantum.plugins.cisco.db import services_models


def get_all_services_bindings():
    """Lists all the services bindings"""
    LOG.debug("get_all_services_bindings() called")
    session = db.get_session()
    try:
        bindings = session.query(services_models.ServicesBinding).\
          all()
        return bindings
    except exc.NoResultFound:
        return []


def get_service_bindings(service_id):
    """Lists services bindings for a service_id"""
    LOG.debug("get_service_bindings() called")
    session = db.get_session()
    try:
        bindings = session.query(services_models.ServicesBinding).\
          filter_by(service_id=service_id).\
          one()
        return bindings
    except exc.NoResultFound:
        return []


def add_services_binding(service_id, mngnet_id, nbnet_id, sbnet_id):
    """Adds a services binding"""
    LOG.debug("add_services_binding() called")
    session = db.get_session()
    binding = services_models.ServicesBinding(service_id, mngnet_id, \
                                              nbnet_id, sbnet_id)
    session.add(binding)
    session.flush()
    return binding


def remove_services_binding(service_id):
    """Removes a services binding"""
    LOG.debug("remove_services_binding() called")
    session = db.get_session()
    try:
        binding = session.query(services_models.ServicesBinding).\
          filter_by(service_id=service_id).\
          all()
        for bind in binding:
            session.delete(bind)
        session.flush()
        return binding
    except exc.NoResultFound:
        pass
