# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
# @author: Ryota MIBU

import sqlalchemy as sa

from quantum.db import api as db
from quantum.db import model_base
from quantum.db import models_v2
from quantum.db import securitygroups_db as sg_db
from quantum.extensions import securitygroup as ext_sg
from quantum import manager
from quantum.openstack.common import log as logging
# NOTE (e0ne): this import is needed for config init
from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import models as nmodels


LOG = logging.getLogger(__name__)
OFP_VLAN_NONE = 0xffff


def initialize():
    db.configure_db()


def clear_db(base=model_base.BASEV2):
    db.clear_db(base)


def get_ofc_item(model, id):
    session = db.get_session()
    try:
        return (session.query(model).
                filter_by(id=id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def find_ofc_item(model, quantum_id):
    session = db.get_session()
    try:
        return (session.query(model).
                filter_by(quantum_id=quantum_id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def add_ofc_item(model, id, quantum_id):
    session = db.get_session()
    try:
        item = model(id=id, quantum_id=quantum_id)
        session.add(item)
        session.flush()
    except Exception as exc:
        LOG.exception(exc)
        raise nexc.NECDBException
    return item


def del_ofc_item(model, id):
    session = db.get_session()
    try:
        item = (session.query(model).
                filter_by(id=id).
                one())
        session.delete(item)
        session.flush()
    except sa.orm.exc.NoResultFound:
        LOG.warning(_("_del_ofc_item(): NotFound item "
                      "(model=%(model)s, id=%(id)s) "), locals())


def get_portinfo(id):
    session = db.get_session()
    try:
        return (session.query(nmodels.PortInfo).
                filter_by(id=id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def add_portinfo(id, datapath_id='', port_no=0, vlan_id=OFP_VLAN_NONE, mac=''):
    session = db.get_session()
    try:
        portinfo = nmodels.PortInfo(id=id, datapath_id=datapath_id,
                                    port_no=port_no, vlan_id=vlan_id, mac=mac)
        session.add(portinfo)
        session.flush()
    except Exception as exc:
        LOG.exception(exc)
        raise nexc.NECDBException
    return portinfo


def del_portinfo(id):
    session = db.get_session()
    try:
        portinfo = (session.query(nmodels.PortInfo).
                    filter_by(id=id).
                    one())
        session.delete(portinfo)
        session.flush()
    except sa.orm.exc.NoResultFound:
        LOG.warning(_("del_portinfo(): NotFound portinfo for "
                      "port_id: %s"), id)


def get_port_from_device(port_id):
    """Get port from database"""
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
    plugin = manager.QuantumManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict[ext_sg.SECURITYGROUPS] = [
        sg_id for port, sg_id in port_and_sgs if sg_id]
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address']
                              for ip in port['fixed_ips']]
    return port_dict
