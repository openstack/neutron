# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.


from sqlalchemy.orm import exc

import quantum.db.api as db
import quantum.db.models as models
import ovs_models


def get_vlans():
    session = db.get_session()
    try:
        bindings = session.query(ovs_models.VlanBinding).\
          all()
    except exc.NoResultFound:
        return []
    res = []
    for x in bindings:
        res.append((x.vlan_id, x.network_id))
    return res


def add_vlan_binding(vlanid, netid):
    session = db.get_session()
    binding = ovs_models.VlanBinding(vlanid, netid)
    session.add(binding)
    session.flush()
    return binding.vlan_id


def remove_vlan_binding(netid):
    session = db.get_session()
    try:
        binding = session.query(ovs_models.VlanBinding).\
          filter_by(network_id=netid).\
          one()
        session.delete(binding)
    except exc.NoResultFound:
            pass
    session.flush()
