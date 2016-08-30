# Copyright 2015 OpenStack LLC.
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

from oslo_utils import uuidutils

from neutron.ipam.drivers.neutrondb_ipam import db_models

# Database operations for Neutron's DB-backed IPAM driver


class IpamSubnetManager(object):

    @classmethod
    def load_by_neutron_subnet_id(cls, context, neutron_subnet_id):
        return context.session.query(db_models.IpamSubnet).filter_by(
            neutron_subnet_id=neutron_subnet_id).first()

    def __init__(self, ipam_subnet_id, neutron_subnet_id):
        self._ipam_subnet_id = ipam_subnet_id
        self._neutron_subnet_id = neutron_subnet_id

    @property
    def neutron_id(self):
        return self._neutron_subnet_id

    def create(self, context):
        """Create database models for an IPAM subnet.

        This method creates a subnet resource for the IPAM driver and
        associates it with its neutron identifier, if specified.

        :param context: neutron api request context
        :returns: the idenfier of created IPAM subnet
        """
        if not self._ipam_subnet_id:
            self._ipam_subnet_id = uuidutils.generate_uuid()
        ipam_subnet = db_models.IpamSubnet(
            id=self._ipam_subnet_id,
            neutron_subnet_id=self._neutron_subnet_id)
        context.session.add(ipam_subnet)
        return self._ipam_subnet_id

    @classmethod
    def delete(cls, context, neutron_subnet_id):
        """Delete IPAM subnet.

        IPAM subnet no longer has foreign key to neutron subnet,
        so need to perform delete manually

        :param context: neutron api request context
        :param neutron_subnet_id: neutron subnet id associated with ipam subnet
        """
        return context.session.query(db_models.IpamSubnet).filter_by(
            neutron_subnet_id=neutron_subnet_id).delete()

    def create_pool(self, context, pool_start, pool_end):
        """Create an allocation pool for the subnet.

        This method does not perform any validation on parameters; it simply
        persist data on the database.

        :param pool_start: string expressing the start of the pool
        :param pool_end: string expressing the end of the pool
        :return: the newly created pool object.
        """
        ip_pool = db_models.IpamAllocationPool(
            ipam_subnet_id=self._ipam_subnet_id,
            first_ip=pool_start,
            last_ip=pool_end)
        context.session.add(ip_pool)
        return ip_pool

    def delete_allocation_pools(self, context):
        """Remove all allocation pools for the current subnet.

        :param context: neutron api request context
        """
        context.session.query(db_models.IpamAllocationPool).filter_by(
            ipam_subnet_id=self._ipam_subnet_id).delete()

    def list_pools(self, context):
        """Return pools for the current subnet."""
        return context.session.query(
            db_models.IpamAllocationPool).filter_by(
            ipam_subnet_id=self._ipam_subnet_id)

    def check_unique_allocation(self, context, ip_address):
        """Validate that the IP address on the subnet is not in use."""
        iprequest = context.session.query(db_models.IpamAllocation).filter_by(
            ipam_subnet_id=self._ipam_subnet_id, status='ALLOCATED',
            ip_address=ip_address).first()
        if iprequest:
            return False
        return True

    def list_allocations(self, context, status='ALLOCATED'):
        """Return current allocations for the subnet.

        :param context: neutron api request context
        :param status: IP allocation status
        :returns: a list of IP allocation as instance of
            neutron.ipam.drivers.neutrondb_ipam.db_models.IpamAllocation
        """
        return context.session.query(
            db_models.IpamAllocation).filter_by(
            ipam_subnet_id=self._ipam_subnet_id,
            status=status)

    def create_allocation(self, context, ip_address,
                          status='ALLOCATED'):
        """Create an IP allocation entry.

        :param context: neutron api request context
        :param ip_address: the IP address to allocate
        :param status: IP allocation status
        """
        ip_request = db_models.IpamAllocation(
            ip_address=ip_address,
            status=status,
            ipam_subnet_id=self._ipam_subnet_id)
        context.session.add(ip_request)

    def delete_allocation(self, context, ip_address):
        """Remove an IP allocation for this subnet.

        :param context: neutron api request context
        :param ip_address: IP address for which the allocation entry should
            be removed.
        """
        return context.session.query(db_models.IpamAllocation).filter_by(
            ip_address=ip_address,
            ipam_subnet_id=self._ipam_subnet_id).delete(
                synchronize_session=False)
