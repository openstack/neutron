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

def update_network_binding(netid, ifaceid):
    session = db.get_session()
    # Add to or delete from the bindings table
    if ifaceid == None:
        try:
            binding = session.query(ovs_models.NetworkBinding).\
              filter_by(network_id=netid).\
              one()
            session.delete(binding)
        except exc.NoResultFound:
            raise Exception("No binding found with network_id = %s" % netid)
    else:
        binding = ovs_models.NetworkBinding(netid, ifaceid)
        session.add(binding)

    session.flush()
