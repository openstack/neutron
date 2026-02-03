# Copyright 2025 Samsung SDS. All Rights Reserved
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import ipaddress

import netaddr

import neutron.db.models_v2 as mod
from neutron.db import network_ip_availability_db
from neutron_lib import constants
from neutron_lib.db import api as db_api

TOTAL_IPS_IN_SUBNET = 'total_ips_in_subnet'
TOTAL_IPS_IN_ALLOCATION_POOL = 'total_ips_in_allocation_pool'
USED_IPS_IN_SUBNET = 'used_ips_in_subnet'
USED_IPS_IN_ALLOCATION_POOL = 'used_ips_in_allocation_pool'
FIRST_IP = 'first_ip'
LAST_IP = 'last_ip'
IP_AVAILABILITY_DETAILS = 'ip_availability_details'


class IpAvailabilityDetailsDbMixin(
        network_ip_availability_db.IpAvailabilityMixin):
    """Mixin class to provide detailed IP availability information."""

    @classmethod
    @db_api.CONTEXT_READER
    def get_network_ip_availabilities(cls, context, filters=None):
        res = super().get_network_ip_availabilities(context, filters)
        subnet_total_ips = cls._generate_subnet_total_ips(context,
                                                          filters)
        subnet_used_ips = cls._generat_subnet_used_ips(context,
                                                       filters)
        return cls._add_details_to_result(res, subnet_total_ips,
                                          subnet_used_ips)

    @classmethod
    def _generate_subnet_total_ips(cls, context, filters):
        """Generates a dict whose key=subnet_id, value=total_ips_dict.
        total_ips_dict has key-value:
          - 'total_ips_in_subnet': subnet cidr
          - 'total_ips_in_allocation_pool': the sum of IPs in each allocation
            pools, 0 if there are no allocation pools in the subnet
        """
        subnet_cidr_alloc_query = cls._build_subnet_cidr_alloc_query(context,
                                                                     filters)

        subnet_totals_dict = {}
        for row in subnet_cidr_alloc_query:
            # Skip networks without subnets
            if not row.subnet_id:
                continue

            # CIDR data
            total_ips_in_subnet = netaddr.IPNetwork(
                row.cidr, version=row.ip_version).size
            if row.ip_version == constants.IP_VERSION_4:
                # Exclude network and broadcast addresses.
                total_ips_in_subnet -= 2

            # IPAllocationPool data
            total_ips_in_allocation_pool = 0
            if row.first_ip:
                pool_total = netaddr.IPRange(
                    netaddr.IPAddress(row.first_ip),
                    netaddr.IPAddress(row.last_ip)).size
                cur_total = (
                    subnet_totals_dict.get(row.subnet_id)
                    .get(TOTAL_IPS_IN_ALLOCATION_POOL)
                    if subnet_totals_dict.get(row.subnet_id) else 0
                )
                total_ips_in_allocation_pool = cur_total + pool_total

            subnet_totals_dict[row.subnet_id] = {
                TOTAL_IPS_IN_SUBNET: total_ips_in_subnet,
                TOTAL_IPS_IN_ALLOCATION_POOL: total_ips_in_allocation_pool
            }
        return subnet_totals_dict

    @classmethod
    @db_api.CONTEXT_READER
    def _build_subnet_cidr_alloc_query(cls, context, filters):
        query = context.session.query(
            *cls.common_columns,
            mod.IPAllocationPool.first_ip,
            mod.IPAllocationPool.last_ip,
        )
        query = query.outerjoin(
            mod.Subnet,
            mod.Network.id == mod.Subnet.network_id
        )
        query = query.outerjoin(
            mod.IPAllocationPool,
            mod.Subnet.id == mod.IPAllocationPool.subnet_id)
        return cls._adjust_query_for_filters(query, filters)

    @classmethod
    def _generat_subnet_used_ips(cls, context, filters):
        """Generates a dict whose key=subnet_id, value=used_ips_dict.
        used_ips_dict has key-value:
          - 'used_ips_in_subnet': the sum of used IPs in the subnet (does not
            consider allocation pools)
          - 'used_ips_in_allocation_pool': the sum of used IPs in each
            allocation pool, 0 in case of no allocation pools
        """
        allocation_pools_query = (
            cls._build_allocation_pools_query(context, filters))

        pools_dict = {}
        used_ips_dict = {}

        for row in allocation_pools_query:
            if pools_dict.get(row.subnet_id) is None:
                pools_dict[row.subnet_id] = []
            pools_dict[row.subnet_id].append({
                FIRST_IP: (int(ipaddress.ip_address(row.first_ip))
                           if row.first_ip else None),
                LAST_IP: (int(ipaddress.ip_address(row.last_ip))
                          if row.last_ip else None)
            })
            if used_ips_dict.get(row.subnet_id) is None:
                used_ips_dict[row.subnet_id] = {
                    USED_IPS_IN_SUBNET: 0,
                    USED_IPS_IN_ALLOCATION_POOL: 0
                }

        allocations_query = cls._build_allocations_query(context, filters)

        for row in allocations_query:
            if pools_dict.get(row.subnet_id) is None:
                continue

            used_ips_dict[row.subnet_id][USED_IPS_IN_SUBNET] += 1

            ip_address = int(ipaddress.ip_address(row.ip_address))
            for pool in pools_dict[row.subnet_id]:
                if pool[FIRST_IP] is None:
                    continue
                if pool[FIRST_IP] <= ip_address <= pool[LAST_IP]:
                    used_ips_dict[row.subnet_id][USED_IPS_IN_ALLOCATION_POOL]\
                        += 1

        return used_ips_dict

    @classmethod
    @db_api.CONTEXT_READER
    def _build_allocation_pools_query(cls, context, filters):
        query = context.session.query(
            *cls.common_columns,
            mod.IPAllocationPool.first_ip,
            mod.IPAllocationPool.last_ip
        )
        query = query.outerjoin(
            mod.Subnet,
            mod.Network.id == mod.Subnet.network_id
        )
        query = query.outerjoin(
            mod.IPAllocationPool,
            mod.Subnet.id == mod.IPAllocationPool.subnet_id)
        return cls._adjust_query_for_filters(query, filters)

    @classmethod
    @db_api.CONTEXT_READER
    def _build_allocations_query(cls, context, filters):
        query = context.session.query(
            *cls.common_columns,
            mod.IPAllocation.ip_address
        )
        query = query.outerjoin(
            mod.Subnet,
            mod.Network.id == mod.Subnet.network_id
        )
        query = query.join(
            mod.IPAllocation,
            mod.Subnet.id == mod.IPAllocation.subnet_id
        )
        return cls._adjust_query_for_filters(query, filters)

    @classmethod
    def _add_details_to_result(cls, res, subnet_total_ips, subnet_used_ips):
        for i, net in enumerate(res):
            net_details = {
                TOTAL_IPS_IN_SUBNET: 0,
                TOTAL_IPS_IN_ALLOCATION_POOL: 0,
                USED_IPS_IN_SUBNET: 0,
                USED_IPS_IN_ALLOCATION_POOL: 0
            }

            res_sub = net['subnet_ip_availability']
            for j, sub in enumerate(res_sub):
                sub_id = sub['subnet_id']
                sub_details = {
                    TOTAL_IPS_IN_SUBNET:
                        subnet_total_ips[sub_id][TOTAL_IPS_IN_SUBNET],
                    TOTAL_IPS_IN_ALLOCATION_POOL:
                        subnet_total_ips[sub_id][TOTAL_IPS_IN_ALLOCATION_POOL],
                    USED_IPS_IN_SUBNET:
                        subnet_used_ips[sub_id][USED_IPS_IN_SUBNET],
                    USED_IPS_IN_ALLOCATION_POOL:
                        subnet_used_ips[sub_id][USED_IPS_IN_ALLOCATION_POOL]
                }
                res_sub[j][IP_AVAILABILITY_DETAILS] = sub_details

                net_details[TOTAL_IPS_IN_SUBNET]\
                    += sub_details[TOTAL_IPS_IN_SUBNET]
                net_details[TOTAL_IPS_IN_ALLOCATION_POOL]\
                    += sub_details[TOTAL_IPS_IN_ALLOCATION_POOL]
                net_details[USED_IPS_IN_SUBNET]\
                    += sub_details[USED_IPS_IN_SUBNET]
                net_details[USED_IPS_IN_ALLOCATION_POOL]\
                    += sub_details[USED_IPS_IN_ALLOCATION_POOL]

            res[i][IP_AVAILABILITY_DETAILS] = net_details

        return res
