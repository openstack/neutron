# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
# All Rights Reserved.
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


import logging

from sqlalchemy.orm import exc

import quantum.db.api as db
from quantum.plugins.nicira.nicira_nvp_plugin import nicira_models

LOG = logging.getLogger(__name__)


def get_network_binding(session, network_id):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(network_id=network_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def get_network_binding_by_vlanid(session, vlan_id):
    session = session or db.get_session()
    try:
        binding = (session.query(nicira_models.NvpNetworkBinding).
                   filter_by(vlan_id=vlan_id).
                   one())
        return binding
    except exc.NoResultFound:
        return


def add_network_binding(session, network_id, binding_type, tz_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nicira_models.NvpNetworkBinding(network_id, binding_type,
                                                  tz_uuid, vlan_id)
        session.add(binding)
    return binding
