# Copyright 2016 GoDaddy.
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

import netaddr
from neutron_lib.db import api as db_api
from sqlalchemy import func

import neutron.db.models_v2 as mod

NETWORK_ID = 'network_id'
NETWORK_NAME = 'network_name'
SUBNET_ID = 'subnet_id'
SUBNET_NAME = 'subnet_name'

SUPPORTED_FILTERS = {
    NETWORK_ID: mod.Network.id,
    NETWORK_NAME: mod.Network.name,
    'tenant_id': mod.Network.tenant_id,
    'project_id': mod.Network.project_id,
    'ip_version': mod.Subnet.ip_version,
}
SUPPORTED_FILTER_KEYS = set(SUPPORTED_FILTERS.keys())


class IpAvailabilityMixin(object):
    """Mixin class to query for IP availability."""

    # Columns common to all queries
    common_columns = [
        mod.Network.id.label(NETWORK_ID),
        mod.Subnet.id.label(SUBNET_ID),
        mod.Subnet.cidr,
        mod.Subnet.ip_version
    ]

    # Columns for the network/subnet and used_ip counts
    network_used_ips_columns = list(common_columns)
    network_used_ips_columns.append(mod.Network.name.label(NETWORK_NAME))
    network_used_ips_columns.append(mod.Network.tenant_id)
    network_used_ips_columns.append(mod.Subnet.name.label(SUBNET_NAME))
    # Aggregate query computed column
    network_used_ips_computed_columns = [
        func.count(mod.IPAllocation.subnet_id).label('used_ips')]

    # Columns for total_ips query
    total_ips_columns = list(common_columns)
    total_ips_columns.append(mod.IPAllocationPool.first_ip)
    total_ips_columns.append(mod.IPAllocationPool.last_ip)

    @classmethod
    def get_network_ip_availabilities(cls, context, filters=None):
        """Get IP availability stats on a per subnet basis.

        Returns a list of network summaries which internally contains a list
        of subnet summaries. The used_ip and total_ip counts are returned at
        both levels.
        """

        # Fetch total_ips by subnet
        subnet_total_ips_dict = cls._generate_subnet_total_ips_dict(context,
                                                                    filters)
        # Query network/subnet data along with used IP counts
        record_and_count_query = cls._build_network_used_ip_query(context,
                                                                  filters)
        # Assemble results
        result_dict = {}
        for row in record_and_count_query:
            cls._add_result(row, result_dict,
                            subnet_total_ips_dict.get(row.subnet_id, 0))

        # Convert result back into the list it expects
        net_ip_availabilities = list(result_dict.values())
        return net_ip_availabilities

    @classmethod
    @db_api.CONTEXT_READER
    def _build_network_used_ip_query(cls, context, filters):
        # Generate a query to gather network/subnet/used_ips.
        # Ensure query is tolerant of missing child table data (outerjoins)
        # Process these outerjoin columns assuming their values may be None
        query = context.session.query()
        query = query.add_columns(*cls.network_used_ips_columns)
        query = query.add_columns(*cls.network_used_ips_computed_columns)
        query = query.outerjoin(mod.Subnet,
                                mod.Network.id == mod.Subnet.network_id)
        query = query.outerjoin(mod.IPAllocation,
                                mod.Subnet.id == mod.IPAllocation.subnet_id)
        query = query.group_by(*cls.network_used_ips_columns)

        return cls._adjust_query_for_filters(query, filters)

    @classmethod
    @db_api.CONTEXT_READER
    def _build_total_ips_query(cls, context, filters):
        query = context.session.query()
        query = query.add_columns(*cls.total_ips_columns)
        query = query.outerjoin(mod.Subnet,
                                mod.Network.id == mod.Subnet.network_id)
        query = query.outerjoin(
                mod.IPAllocationPool,
                mod.Subnet.id == mod.IPAllocationPool.subnet_id)
        return cls._adjust_query_for_filters(query, filters)

    @classmethod
    def _generate_subnet_total_ips_dict(cls, context, filters):
        """Generates a dict whose key=subnet_id, value=total_ips in subnet"""

        # Query to get total_ips counts
        total_ips_query = cls._build_total_ips_query(context, filters)

        subnet_totals_dict = {}
        for row in total_ips_query:
            # Skip networks without subnets
            if not row.subnet_id:
                continue

            # Add IPAllocationPool data
            if row.last_ip:
                pool_total = netaddr.IPRange(
                        netaddr.IPAddress(row.first_ip),
                        netaddr.IPAddress(row.last_ip)).size
                cur_total = subnet_totals_dict.get(row.subnet_id, 0)
                subnet_totals_dict[row.subnet_id] = cur_total + pool_total
            else:
                subnet_totals_dict[row.subnet_id] = netaddr.IPNetwork(
                        row.cidr, version=row.ip_version).size

        return subnet_totals_dict

    @classmethod
    def _adjust_query_for_filters(cls, query, filters):
        # The intersect of sets gets us applicable filter keys (others ignored)
        common_keys = filters.keys() & SUPPORTED_FILTER_KEYS
        for key in common_keys:
            filter_vals = filters[key]
            if filter_vals:
                query = query.filter(SUPPORTED_FILTERS[key].in_(filter_vals))
        return query

    @classmethod
    def _add_result(cls, db_row, result_dict, subnet_total_ips):
        # Find network in results. Create and add if missing
        if db_row.network_id in result_dict:
            network = result_dict[db_row.network_id]
        else:
            network = {NETWORK_ID: db_row.network_id,
                       NETWORK_NAME: db_row.network_name,
                       'tenant_id': db_row.tenant_id,
                       'project_id': db_row.tenant_id,
                       'subnet_ip_availability': [],
                       'used_ips': 0, 'total_ips': 0}
            result_dict[db_row.network_id] = network

        # Only add subnet data if outerjoin rows have it
        if db_row.subnet_id:
            cls._add_subnet_data_to_net(db_row, network, subnet_total_ips)

    @classmethod
    def _add_subnet_data_to_net(cls, db_row, network_dict, subnet_total_ips):
        subnet = {
            SUBNET_ID: db_row.subnet_id,
            'ip_version': db_row.ip_version,
            'cidr': db_row.cidr,
            SUBNET_NAME: db_row.subnet_name,
            'used_ips': db_row.used_ips if db_row.used_ips else 0,
            'total_ips': subnet_total_ips
        }
        # Attach subnet result and rollup subnet sums into the parent
        network_dict['subnet_ip_availability'].append(subnet)
        network_dict['total_ips'] += subnet['total_ips']
        network_dict['used_ips'] += subnet['used_ips']
