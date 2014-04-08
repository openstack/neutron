# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.

"""
Neutron Plug-in for PLUMgrid Virtual Networking Infrastructure (VNI)
This plugin will forward authenticated REST API calls
to the PLUMgrid Network Management System called Director
"""

from plumgridlib import plumlib

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class Plumlib(object):
    """
    Class PLUMgrid Python Library. This library is a third-party tool
    needed by PLUMgrid plugin to implement all core API in Neutron.
    """

    def __init__(self):
        LOG.info(_('Python PLUMgrid Library Started '))

    def director_conn(self, director_plumgrid, director_port, timeout,
                      director_admin, director_password):
        self.plumlib = plumlib.Plumlib(director_plumgrid,
                                       director_port,
                                       timeout,
                                       director_admin,
                                       director_password)

    def create_network(self, tenant_id, net_db, network):
        self.plumlib.create_network(tenant_id, net_db, network)

    def update_network(self, tenant_id, net_id):
        self.plumlib.update_network(tenant_id, net_id)

    def delete_network(self, net_db, net_id):
        self.plumlib.delete_network(net_db, net_id)

    def create_subnet(self, sub_db, net_db, ipnet):
        self.plumlib.create_subnet(sub_db, net_db, ipnet)

    def update_subnet(self, orig_sub_db, new_sub_db, ipnet):
        self.plumlib.update_subnet(orig_sub_db, new_sub_db, ipnet)

    def delete_subnet(self, tenant_id, net_db, net_id):
        self.plumlib.delete_subnet(tenant_id, net_db, net_id)

    def create_port(self, port_db, router_db):
        self.plumlib.create_port(port_db, router_db)

    def update_port(self, port_db, router_db):
        self.plumlib.update_port(port_db, router_db)

    def delete_port(self, port_db, router_db):
        self.plumlib.delete_port(port_db, router_db)

    def create_router(self, tenant_id, router_db):
        self.plumlib.create_router(tenant_id, router_db)

    def update_router(self, router_db, router_id):
        self.plumlib.update_router(router_db, router_id)

    def delete_router(self, tenant_id, router_id):
        self.plumlib.delete_router(tenant_id, router_id)

    def add_router_interface(self, tenant_id, router_id, port_db, ipnet):
        self.plumlib.add_router_interface(tenant_id, router_id, port_db, ipnet)

    def remove_router_interface(self, tenant_id, net_id, router_id):
        self.plumlib.remove_router_interface(tenant_id, net_id, router_id)

    def create_floatingip(self, floating_ip):
        self.plumlib.create_floatingip(floating_ip)

    def update_floatingip(self, floating_ip_orig, floating_ip, id):
        self.plumlib.update_floatingip(floating_ip_orig, floating_ip, id)

    def delete_floatingip(self, floating_ip_orig, id):
        self.plumlib.delete_floatingip(floating_ip_orig, id)

    def disassociate_floatingips(self, floating_ip, port_id):
        self.plumlib.disassociate_floatingips(floating_ip, port_id)
