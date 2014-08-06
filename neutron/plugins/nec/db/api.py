# Copyright 2012 NEC Corporation.  All rights reserved.
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

import sqlalchemy as sa

from neutron.db import api as db
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config  # noqa
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import models as nmodels


LOG = logging.getLogger(__name__)
OFP_VLAN_NONE = 0xffff


resource_map = {'ofc_tenant': nmodels.OFCTenantMapping,
                'ofc_network': nmodels.OFCNetworkMapping,
                'ofc_port': nmodels.OFCPortMapping,
                'ofc_router': nmodels.OFCRouterMapping,
                'ofc_packet_filter': nmodels.OFCFilterMapping}


# utitlity methods

def _get_resource_model(resource):
    return resource_map[resource]


def get_ofc_item(session, resource, neutron_id):
    model = _get_resource_model(resource)
    if not model:
        return
    try:
        return session.query(model).filter_by(neutron_id=neutron_id).one()
    except sa.orm.exc.NoResultFound:
        return


def get_ofc_id(session, resource, neutron_id):
    ofc_item = get_ofc_item(session, resource, neutron_id)
    if ofc_item:
        return ofc_item.ofc_id
    else:
        raise nexc.OFCMappingNotFound(resource=resource,
                                      neutron_id=neutron_id)


def exists_ofc_item(session, resource, neutron_id):
    if get_ofc_item(session, resource, neutron_id):
        return True
    else:
        return False


def find_ofc_item(session, resource, ofc_id):
    try:
        model = _get_resource_model(resource)
        params = dict(ofc_id=ofc_id)
        return (session.query(model).filter_by(**params).one())
    except sa.orm.exc.NoResultFound:
        return None


def add_ofc_item(session, resource, neutron_id, ofc_id):
    try:
        model = _get_resource_model(resource)
        params = dict(neutron_id=neutron_id, ofc_id=ofc_id)
        item = model(**params)
        with session.begin(subtransactions=True):
            session.add(item)
            session.flush()
    except Exception as exc:
        LOG.exception(exc)
        raise nexc.NECDBException(reason=exc.message)
    return item


def del_ofc_item(session, resource, neutron_id):
    try:
        model = _get_resource_model(resource)
        with session.begin(subtransactions=True):
            item = session.query(model).filter_by(neutron_id=neutron_id).one()
            session.delete(item)
        return True
    except sa.orm.exc.NoResultFound:
        LOG.warning(_("del_ofc_item(): NotFound item "
                      "(resource=%(resource)s, id=%(id)s) "),
                    {'resource': resource, 'id': neutron_id})
        return False


def get_portinfo(session, id):
    try:
        return (session.query(nmodels.PortInfo).
                filter_by(id=id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def add_portinfo(session, id, datapath_id='', port_no=0,
                 vlan_id=OFP_VLAN_NONE, mac=''):
    try:
        portinfo = nmodels.PortInfo(id=id, datapath_id=datapath_id,
                                    port_no=port_no, vlan_id=vlan_id, mac=mac)
        with session.begin(subtransactions=True):
            session.add(portinfo)
    except Exception as exc:
        LOG.exception(exc)
        raise nexc.NECDBException(reason=exc.message)
    return portinfo


def del_portinfo(session, id):
    try:
        with session.begin(subtransactions=True):
            portinfo = session.query(nmodels.PortInfo).filter_by(id=id).one()
            session.delete(portinfo)
    except sa.orm.exc.NoResultFound:
        LOG.warning(_("del_portinfo(): NotFound portinfo for "
                      "port_id: %s"), id)


def get_active_ports_on_ofc(context, network_id, port_id=None):
    """Retrieve ports on OFC on a given network.

    It returns a list of tuple (neutron port_id, OFC id).
    """
    query = context.session.query(nmodels.OFCPortMapping)
    query = query.join(models_v2.Port,
                       nmodels.OFCPortMapping.neutron_id == models_v2.Port.id)
    query = query.filter(models_v2.Port.network_id == network_id)
    if port_id:
        query = query.filter(nmodels.OFCPortMapping.neutron_id == port_id)

    return [(p['neutron_id'], p['ofc_id']) for p in query]


def get_port_from_device(port_id):
    """Get port from database."""
    LOG.debug(_("get_port_with_securitygroups() called:port_id=%s"), port_id)
    session = db.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    query = session.query(models_v2.Port,
                          sg_db.SecurityGroupPortBinding.security_group_id)
    query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                            models_v2.Port.id == sg_binding_port)
    query = query.filter(models_v2.Port.id == port_id)
    port_and_sgs = query.all()
    if not port_and_sgs:
        return None
    port = port_and_sgs[0][0]
    plugin = manager.NeutronManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict[ext_sg.SECURITYGROUPS] = [
        sg_id for port_, sg_id in port_and_sgs if sg_id]
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict
