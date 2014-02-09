# Copyright (c) 2013 OpenStack Foundation
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

from sqlalchemy.orm import exc

from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log
from neutron.openstack.common import uuidutils
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import models

LOG = log.getLogger(__name__)


def add_network_segment(session, network_id, segment):
    with session.begin(subtransactions=True):
        record = models.NetworkSegment(
            id=uuidutils.generate_uuid(),
            network_id=network_id,
            network_type=segment.get(api.NETWORK_TYPE),
            physical_network=segment.get(api.PHYSICAL_NETWORK),
            segmentation_id=segment.get(api.SEGMENTATION_ID)
        )
        session.add(record)
    LOG.info(_("Added segment %(id)s of type %(network_type)s for network"
               " %(network_id)s"),
             {'id': record.id,
              'network_type': record.network_type,
              'network_id': record.network_id})


def get_network_segments(session, network_id):
    with session.begin(subtransactions=True):
        records = (session.query(models.NetworkSegment).
                   filter_by(network_id=network_id))
        return [{api.ID: record.id,
                 api.NETWORK_TYPE: record.network_type,
                 api.PHYSICAL_NETWORK: record.physical_network,
                 api.SEGMENTATION_ID: record.segmentation_id}
                for record in records]


def ensure_port_binding(session, port_id):
    with session.begin(subtransactions=True):
        try:
            record = (session.query(models.PortBinding).
                      filter_by(port_id=port_id).
                      one())
        except exc.NoResultFound:
            record = models.PortBinding(
                port_id=port_id,
                vif_type=portbindings.VIF_TYPE_UNBOUND)
            session.add(record)
        return record


def get_port(session, port_id):
    """Get port record for update within transcation."""

    with session.begin(subtransactions=True):
        try:
            record = (session.query(models_v2.Port).
                      filter(models_v2.Port.id.startswith(port_id)).
                      one())
            return record
        except exc.NoResultFound:
            return
        except exc.MultipleResultsFound:
            LOG.error(_("Multiple ports have port_id starting with %s"),
                      port_id)
            return


def get_port_from_device_mac(device_mac):
    LOG.debug(_("get_port_from_device_mac() called for mac %s"), device_mac)
    session = db_api.get_session()
    qry = session.query(models_v2.Port).filter_by(mac_address=device_mac)
    return qry.first()


def get_port_and_sgs(port_id):
    """Get port from database with security group info."""

    LOG.debug(_("get_port_and_sgs() called for port_id %s"), port_id)
    session = db_api.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    with session.begin(subtransactions=True):
        query = session.query(models_v2.Port,
                              sg_db.SecurityGroupPortBinding.security_group_id)
        query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                                models_v2.Port.id == sg_binding_port)
        query = query.filter(models_v2.Port.id.startswith(port_id))
        port_and_sgs = query.all()
        if not port_and_sgs:
            return
        port = port_and_sgs[0][0]
        plugin = manager.NeutronManager.get_plugin()
        port_dict = plugin._make_port_dict(port)
        port_dict['security_groups'] = [
            sg_id for port_, sg_id in port_and_sgs if sg_id]
        port_dict['security_group_rules'] = []
        port_dict['security_group_source_groups'] = []
        port_dict['fixed_ips'] = [ip['ip_address']
                                  for ip in port['fixed_ips']]
        return port_dict


def get_port_binding_host(port_id):
    session = db_api.get_session()
    with session.begin(subtransactions=True):
        try:
            query = (session.query(models.PortBinding).
                     filter(models.PortBinding.port_id.startswith(port_id)).
                     one())
        except exc.NoResultFound:
            LOG.debug(_("No binding found for port %(port_id)s"),
                      {'port_id': port_id})
            return
    return query.host
