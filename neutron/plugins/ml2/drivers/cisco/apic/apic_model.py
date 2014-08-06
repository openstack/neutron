# Copyright (c) 2014 Cisco Systems Inc.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import api as db_api
from neutron.db import model_base

from neutron.db import models_v2
from neutron.plugins.ml2 import models as models_ml2


class RouterContract(model_base.BASEV2, models_v2.HasTenant):

    """Contracts created on the APIC.

    tenant_id represents the owner (APIC side) of the contract.
    router_id is the UUID of the router (Neutron side) this contract is
    referring to.
    """

    __tablename__ = 'cisco_ml2_apic_contracts'

    router_id = sa.Column(sa.String(64), sa.ForeignKey('routers.id',
                                                       ondelete='CASCADE'),
                          primary_key=True)


class HostLink(model_base.BASEV2):

    """Connectivity of host links."""

    __tablename__ = 'cisco_ml2_apic_host_links'

    host = sa.Column(sa.String(255), nullable=False, primary_key=True)
    ifname = sa.Column(sa.String(64), nullable=False, primary_key=True)
    ifmac = sa.Column(sa.String(32), nullable=True)
    swid = sa.Column(sa.String(32), nullable=False)
    module = sa.Column(sa.String(32), nullable=False)
    port = sa.Column(sa.String(32), nullable=False)


class ApicName(model_base.BASEV2):
    """Mapping of names created on the APIC."""

    __tablename__ = 'cisco_ml2_apic_names'

    neutron_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    neutron_type = sa.Column(sa.String(32), nullable=False, primary_key=True)
    apic_name = sa.Column(sa.String(255), nullable=False)


class ApicDbModel(object):

    """DB Model to manage all APIC DB interactions."""

    def __init__(self):
        self.session = db_api.get_session()

    def get_contract_for_router(self, router_id):
        """Returns the specified router's contract."""
        return self.session.query(RouterContract).filter_by(
            router_id=router_id).first()

    def write_contract_for_router(self, tenant_id, router_id):
        """Stores a new contract for the given tenant."""
        contract = RouterContract(tenant_id=tenant_id,
                                  router_id=router_id)
        with self.session.begin(subtransactions=True):
            self.session.add(contract)
        return contract

    def update_contract_for_router(self, tenant_id, router_id):
        with self.session.begin(subtransactions=True):
            contract = self.session.query(RouterContract).filter_by(
                router_id=router_id).with_lockmode('update').first()
            if contract:
                contract.tenant_id = tenant_id
                self.session.merge(contract)
            else:
                self.write_contract_for_router(tenant_id, router_id)

    def delete_contract_for_router(self, router_id):
        with self.session.begin(subtransactions=True):
            try:
                self.session.query(RouterContract).filter_by(
                    router_id=router_id).delete()
            except orm.exc.NoResultFound:
                return

    def add_hostlink(self, host, ifname, ifmac, swid, module, port):
        link = HostLink(host=host, ifname=ifname, ifmac=ifmac,
                       swid=swid, module=module, port=port)
        with self.session.begin(subtransactions=True):
            self.session.merge(link)

    def get_hostlinks(self):
        return self.session.query(HostLink).all()

    def get_hostlink(self, host, ifname):
        return self.session.query(HostLink).filter_by(
            host=host, ifname=ifname).first()

    def get_hostlinks_for_host(self, host):
        return self.session.query(HostLink).filter_by(
            host=host).all()

    def get_hostlinks_for_host_switchport(self, host, swid, module, port):
        return self.session.query(HostLink).filter_by(
            host=host, swid=swid, module=module, port=port).all()

    def get_hostlinks_for_switchport(self, swid, module, port):
        return self.session.query(HostLink).filter_by(
            swid=swid, module=module, port=port).all()

    def delete_hostlink(self, host, ifname):
        with self.session.begin(subtransactions=True):
            try:
                self.session.query(HostLink).filter_by(host=host,
                                                       ifname=ifname).delete()
            except orm.exc.NoResultFound:
                return

    def get_switches(self):
        return self.session.query(HostLink.swid).distinct()

    def get_modules_for_switch(self, swid):
        return self.session.query(
            HostLink.module).filter_by(swid=swid).distinct()

    def get_ports_for_switch_module(self, swid, module):
        return self.session.query(
            HostLink.port).filter_by(swid=swid, module=module).distinct()

    def get_switch_and_port_for_host(self, host):
        return self.session.query(
            HostLink.swid, HostLink.module, HostLink.port).filter_by(
                host=host).distinct()

    def get_tenant_network_vlan_for_host(self, host):
        pb = models_ml2.PortBinding
        po = models_v2.Port
        ns = models_ml2.NetworkSegment
        return self.session.query(
            po.tenant_id, ns.network_id, ns.segmentation_id).filter(
            po.id == pb.port_id).filter(pb.host == host).filter(
                po.network_id == ns.network_id).distinct()

    def add_apic_name(self, neutron_id, neutron_type, apic_name):
        name = ApicName(neutron_id=neutron_id,
                        neutron_type=neutron_type,
                        apic_name=apic_name)
        with self.session.begin(subtransactions=True):
            self.session.add(name)

    def update_apic_name(self, neutron_id, neutron_type, apic_name):
        with self.session.begin(subtransactions=True):
            name = self.session.query(ApicName).filter_by(
                neutron_id=neutron_id,
                neutron_type=neutron_type).with_lockmode('update').first()
            if name:
                name.apic_name = apic_name
                self.session.merge(name)
            else:
                self.add_apic_name(neutron_id, neutron_type, apic_name)

    def get_apic_names(self):
        return self.session.query(ApicName).all()

    def get_apic_name(self, neutron_id, neutron_type):
        return self.session.query(ApicName.apic_name).filter_by(
            neutron_id=neutron_id, neutron_type=neutron_type).first()

    def delete_apic_name(self, neutron_id):
        with self.session.begin(subtransactions=True):
            try:
                self.session.query(ApicName).filter_by(
                    neutron_id=neutron_id).delete()
            except orm.exc.NoResultFound:
                return
