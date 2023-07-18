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

import netaddr
from neutron_lib.api import validators
from neutron_lib import constants as const
from neutron_lib.db import model_query
from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils

from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import and_, or_
from sqlalchemy.sql import exists

from neutron.db.models import dns as dns_models
from neutron.db.models import segment as segment_model
from neutron.db.models import subnet_service_type
from neutron.db import models_v2
from neutron.ipam import exceptions as ipam_exceptions
from neutron.objects import base
from neutron.objects import network
from neutron.objects import rbac_db
from neutron.services.segments import exceptions as segment_exc


@base.NeutronObjectRegistry.register
class DNSNameServer(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.DNSNameServer

    primary_keys = ['address', 'subnet_id']

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    fields = {
        'address': obj_fields.StringField(),
        'subnet_id': common_types.UUIDField(),
        'order': obj_fields.IntegerField()
    }

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        """Fetch DNSNameServer objects with default sort by 'order' field.
        """
        if not _pager:
            _pager = base.Pager()
        if not _pager.sorts:
            # (NOTE) True means ASC, False is DESC
            _pager.sorts = [('order', True)]
        return super(DNSNameServer, cls).get_objects(context, _pager,
                                                     validate_filters,
                                                     **kwargs)


@base.NeutronObjectRegistry.register
class Route(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.SubnetRoute

    primary_keys = ['destination', 'nexthop', 'subnet_id']

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    fields = {
        'subnet_id': common_types.UUIDField(),
        'destination': common_types.IPNetworkField(),
        'nexthop': obj_fields.IPAddressField()
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Route, cls).modify_fields_from_db(db_obj)
        if 'destination' in result:
            result['destination'] = net_utils.AuthenticIPNetwork(
                result['destination'])
        if 'nexthop' in result:
            result['nexthop'] = netaddr.IPAddress(result['nexthop'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Route, cls).modify_fields_to_db(fields)
        if 'destination' in result:
            result['destination'] = cls.filter_to_str(result['destination'])
        if 'nexthop' in fields:
            result['nexthop'] = cls.filter_to_str(result['nexthop'])
        return result


@base.NeutronObjectRegistry.register
class IPAllocationPool(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.IPAllocationPool

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    fields_need_translation = {
        'start': 'first_ip',
        'end': 'last_ip'
    }

    fields = {
        'id': common_types.UUIDField(),
        'subnet_id': common_types.UUIDField(),
        'start': obj_fields.IPAddressField(),
        'end': obj_fields.IPAddressField()
    }

    fields_no_update = ['subnet_id']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(IPAllocationPool, cls).modify_fields_from_db(db_obj)
        if 'start' in result:
            result['start'] = netaddr.IPAddress(result['start'])
        if 'end' in result:
            result['end'] = netaddr.IPAddress(result['end'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(IPAllocationPool, cls).modify_fields_to_db(fields)
        if 'first_ip' in result:
            result['first_ip'] = cls.filter_to_str(result['first_ip'])
        if 'last_ip' in result:
            result['last_ip'] = cls.filter_to_str(result['last_ip'])
        return result


@base.NeutronObjectRegistry.register
class SubnetServiceType(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = subnet_service_type.SubnetServiceType

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    primary_keys = ['subnet_id', 'service_type']

    fields = {
        'subnet_id': common_types.UUIDField(),
        'service_type': obj_fields.StringField()
    }

    @classmethod
    def query_filter_service_subnets(cls, query, service_type):
        # TODO(tuanvu): find OVO-like solution for handling "join queries"
        Subnet = models_v2.Subnet
        ServiceType = subnet_service_type.SubnetServiceType
        query = query.add_entity(ServiceType)
        query = query.outerjoin(ServiceType)
        query = query.filter(or_(
            ServiceType.service_type.is_(None),
            ServiceType.service_type == service_type,
            # Allow DHCP ports to be created on subnets of any
            # service type when DHCP is enabled on the subnet.
            and_(Subnet.enable_dhcp.is_(True),
                 service_type == const.DEVICE_OWNER_DHCP)))

        if query._group_by_clauses:
            # If the "Subnet" query has a "GROUP BY" clause (that happens when
            # a non-admin user has executed the query, that requires the join
            # of the RBAC registers), it is needed to add the
            # "SubnetServiceType" fields to this clause too.
            query = query.group_by(ServiceType.subnet_id,
                                   ServiceType.service_type)

        return query.from_self(Subnet)


# RBAC metaclass is not applied here because 'shared' attribute of Subnet
# is dependent on Network 'shared' state, and in Subnet object
# it can be read-only. The necessary changes are applied manually:
#   - defined 'shared' attribute in 'fields'
#   - added 'shared' to synthetic_fields
#   - registered extra_filter_name for 'shared' attribute
#   - added loading shared attribute based on network 'rbac_entries'
@base.NeutronObjectRegistry.register
class Subnet(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add dns_publish_fixed_ip field
    VERSION = '1.1'

    db_model = models_v2.Subnet

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'network_id': common_types.UUIDField(),
        'segment_id': common_types.UUIDField(nullable=True),
        # NOTE: subnetpool_id can be 'prefix_delegation' string
        # when the IPv6 Prefix Delegation is enabled
        'subnetpool_id': obj_fields.StringField(nullable=True),
        'ip_version': common_types.IPVersionEnumField(),
        'cidr': common_types.IPNetworkField(),
        'gateway_ip': obj_fields.IPAddressField(nullable=True),
        'allocation_pools': obj_fields.ListOfObjectsField('IPAllocationPool',
                                                          nullable=True),
        'enable_dhcp': obj_fields.BooleanField(nullable=True),
        'shared': obj_fields.BooleanField(nullable=True),
        'dns_nameservers': obj_fields.ListOfObjectsField('DNSNameServer',
                                                         nullable=True),
        'dns_publish_fixed_ip': obj_fields.BooleanField(nullable=True),
        'host_routes': obj_fields.ListOfObjectsField('Route', nullable=True),
        'ipv6_ra_mode': common_types.IPV6ModeEnumField(nullable=True),
        'ipv6_address_mode': common_types.IPV6ModeEnumField(nullable=True),
        'service_types': obj_fields.ListOfStringsField(nullable=True)
    }

    synthetic_fields = ['allocation_pools', 'dns_nameservers',
                        'dns_publish_fixed_ip', 'host_routes',
                        'service_types', 'shared']

    foreign_keys = {'Network': {'network_id': 'id'}}

    fields_no_update = ['project_id', 'network_id']

    fields_need_translation = {
        'host_routes': 'routes'
    }

    def __init__(self, context=None, **kwargs):
        super(Subnet, self).__init__(context, **kwargs)
        self.add_extra_filter_name('shared')

    def obj_load_attr(self, attrname):
        if attrname == 'dns_publish_fixed_ip':
            return self._load_dns_publish_fixed_ip()
        if attrname == 'shared':
            return self._load_shared()
        if attrname == 'service_types':
            return self._load_service_types()
        super(Subnet, self).obj_load_attr(attrname)

    def _load_dns_publish_fixed_ip(self, db_obj=None):
        if db_obj:
            object_data = db_obj.get('dns_publish_fixed_ip', None)
        else:
            object_data = SubnetDNSPublishFixedIP.get_objects(
                    self.obj_context,
                    subnet_id=self.id)

        dns_publish_fixed_ip = False
        if object_data:
            dns_publish_fixed_ip = object_data.get(
                    'dns_publish_fixed_ip')
        setattr(self, 'dns_publish_fixed_ip', dns_publish_fixed_ip)
        self.obj_reset_changes(['dns_publish_fixed_ip'])

    def _load_shared(self, db_obj=None):
        if db_obj:
            # NOTE(korzen) db_obj is passed when Subnet object is loaded
            # from DB
            rbac_entries = db_obj.get('rbac_entries') or {}
            shared = (rbac_db.RbacNeutronDbObjectMixin.
                      is_network_shared(self.obj_context, rbac_entries))
        else:
            # NOTE(korzen) this case is used when Subnet object was
            # instantiated and without DB interaction (get_object(s), update,
            # create), it should be rare case to load 'shared' by that method
            shared = (rbac_db.RbacNeutronDbObjectMixin.
                      get_shared_with_project(self.obj_context.elevated(),
                                              network.NetworkRBAC,
                                              self.network_id,
                                              self.project_id))
        setattr(self, 'shared', shared)
        self.obj_reset_changes(['shared'])

    def _load_service_types(self, db_obj=None):
        if db_obj:
            service_types = db_obj.get('service_types', [])
        else:
            service_types = SubnetServiceType.get_objects(self.obj_context,
                                                          subnet_id=self.id)

        self.service_types = [service_type['service_type'] for
                              service_type in service_types]
        self.obj_reset_changes(['service_types'])

    def from_db_object(self, db_obj):
        super(Subnet, self).from_db_object(db_obj)
        self._load_dns_publish_fixed_ip(db_obj)
        self._load_shared(db_obj)
        self._load_service_types(db_obj)

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Subnet, cls).modify_fields_from_db(db_obj)
        if 'cidr' in result:
            result['cidr'] = net_utils.AuthenticIPNetwork(result['cidr'])
        if 'gateway_ip' in result and result['gateway_ip'] is not None:
            result['gateway_ip'] = netaddr.IPAddress(result['gateway_ip'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Subnet, cls).modify_fields_to_db(fields)
        if 'cidr' in result:
            result['cidr'] = cls.filter_to_str(result['cidr'])
        if 'gateway_ip' in result and result['gateway_ip'] is not None:
            result['gateway_ip'] = cls.filter_to_str(result['gateway_ip'])
        return result

    @classmethod
    def find_candidate_subnets(cls, context, network_id, host, service_type,
                               fixed_configured, fixed_ips,
                               distributed_service=False):
        """Find canditate subnets for the network, host, and service_type"""
        query = cls.query_subnets_on_network(context, network_id)
        query = SubnetServiceType.query_filter_service_subnets(
            query, service_type)

        # Select candidate subnets and return them
        if not cls.is_host_set(host):
            if fixed_configured:
                # If fixed_ips in request and host is not known all subnets on
                # the network are candidates. Host/Segment will be validated
                # on port update with binding:host_id set. Allocation _cannot_
                # be deferred as requested fixed_ips would then be lost.
                return cls._query_filter_by_fixed_ips_segment(
                    query, fixed_ips,
                    allow_multiple_segments=distributed_service).all()
            # If the host isn't known, we can't allocate on a routed network.
            # So, exclude any subnets attached to segments.
            return cls._query_exclude_subnets_on_segments(query).all()

        # The host is known. Consider both routed and non-routed networks
        results = cls._query_filter_by_segment_host_mapping(query, host).all()

        # For now, we're using a simplifying assumption that a host will only
        # touch one segment in a given routed network.  Raise exception
        # otherwise.  This restriction may be relaxed as use cases for multiple
        # mappings are understood.
        segment_ids = {subnet.segment_id
                       for subnet, mapping in results
                       if mapping}
        if 1 < len(segment_ids):
            raise segment_exc.HostConnectedToMultipleSegments(
                host=host, network_id=network_id)

        return [subnet for subnet, _mapping in results]

    @classmethod
    def _query_filter_by_fixed_ips_segment(cls, query, fixed_ips,
            allow_multiple_segments=False):
        """Excludes subnets not on the same segment as fixed_ips

        :raises: FixedIpsSubnetsNotOnSameSegment
        """
        segment_ids = []
        subnets = query.all()

        for fixed_ip in fixed_ips:
            subnet = None
            if 'subnet_id' in fixed_ip:
                try:
                    subnet = [
                        sub
                        for sub in subnets
                        if sub['id'] == fixed_ip['subnet_id']
                    ][0]
                except IndexError:
                    # NOTE(hjensas): The subnet is invalid for the network,
                    # return all subnets. This will be detected in following
                    # IPAM code and some exception will be raised.
                    return query
            elif 'ip_address' in fixed_ip:
                ip = netaddr.IPNetwork(fixed_ip['ip_address'])

                for s in subnets:
                    if ip in netaddr.IPNetwork(s.cidr):
                        subnet = s
                        break
                if not subnet:
                    # NOTE(hjensas): The ip address is invalid, return all
                    # subnets. This will be detected in following IPAM code
                    # and some exception will be raised.
                    return query

            if subnet and subnet.segment_id not in segment_ids:
                segment_ids.append(subnet.segment_id)

            if 1 < len(segment_ids) and not allow_multiple_segments:
                raise segment_exc.FixedIpsSubnetsNotOnSameSegment()

        if allow_multiple_segments:
            return query

        segment_id = None if not segment_ids else segment_ids[0]
        return query.filter(cls.db_model.segment_id == segment_id)

    @classmethod
    def _query_filter_by_segment_host_mapping(cls, query, host):
        # TODO(tuanvu): find OVO-like solution for handling "join queries" and
        #               write unit test for this function
        """Excludes subnets on segments not reachable by the host

        The query gets two kinds of subnets: those that are on segments that
        the host can reach and those that are not on segments at all (assumed
        reachable by all hosts). Hence, subnets on segments that the host
        *cannot* reach are excluded.
        """
        SegmentHostMapping = segment_model.SegmentHostMapping

        # A host has been provided.  Consider these two scenarios
        # 1. Not a routed network:  subnets are not on segments
        # 2. Is a routed network:  only subnets on segments mapped to host
        # The following join query returns results for either.  The two are
        # guaranteed to be mutually exclusive when subnets are created.
        query = query.add_entity(SegmentHostMapping)
        query = query.outerjoin(
            SegmentHostMapping,
            and_(cls.db_model.segment_id == SegmentHostMapping.segment_id,
                 SegmentHostMapping.host == host))

        # Essentially "segment_id IS NULL XNOR host IS NULL"
        query = query.filter(or_(and_(cls.db_model.segment_id.isnot(None),
                                      SegmentHostMapping.host.isnot(None)),
                                 and_(cls.db_model.segment_id.is_(None),
                                      SegmentHostMapping.host.is_(None))))
        return query

    @classmethod
    def query_subnets_on_network(cls, context, network_id):
        query = model_query.get_collection_query(context, cls.db_model)
        return query.filter(cls.db_model.network_id == network_id)

    @classmethod
    def _query_exclude_subnets_on_segments(cls, query):
        """Excludes all subnets associated with segments

        For the case where the host is not known, we don't consider any subnets
        that are on segments. But, we still consider subnets that are not
        associated with any segment (i.e. for non-routed networks).
        """
        return query.filter(cls.db_model.segment_id.is_(None))

    @classmethod
    def is_host_set(cls, host):
        """Utility to tell if the host is set in the port binding"""
        # This seems redundant, but its not. Host is unset if its None, '',
        # or ATTR_NOT_SPECIFIED due to differences in host binding
        # implementations.
        return host and validators.is_attr_set(host)

    @classmethod
    def network_has_no_subnet(cls, context, network_id, host, service_type):
        # Determine why we found no subnets to raise the right error
        query = cls.query_subnets_on_network(context, network_id)

        if cls.is_host_set(host):
            # Empty because host isn't mapped to a segment with a subnet?
            s_query = query.filter(cls.db_model.segment_id.isnot(None))
            if s_query.limit(1).count() != 0:
                # It is a routed network but no subnets found for host
                raise segment_exc.HostNotConnectedToAnySegment(
                    host=host, network_id=network_id)

        if not query.limit(1).count():
            # Network has *no* subnets of any kind. This isn't an error.
            return True

        # Does filtering ineligible service subnets makes the list empty?
        query = SubnetServiceType.query_filter_service_subnets(
            query, service_type)
        if query.limit(1).count():
            # No, must be a deferred IP port because there are matching
            # subnets. Happens on routed networks when host isn't known.
            raise ipam_exceptions.DeferIpam()
        return False

    @classmethod
    def get_subnet_cidrs(cls, context):
        return [
            {'id': subnet[0], 'cidr': subnet[1]} for subnet in
            context.session.query(cls.db_model.id, cls.db_model.cidr).all()]

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):  # version 1.1 adds "dns_publish_fixed_ip"
            primitive.pop('dns_publish_fixed_ip', None)

    @classmethod
    def get_subnet_segment_ids(cls, context, network_id,
                               ignored_service_type=None,
                               subnet_id=None):
        query = context.session.query(cls.db_model.segment_id)
        query = query.filter(cls.db_model.network_id == network_id)

        # NOTE(zigo): Subnet who hold the type ignored_service_type should be
        # removed from the segment list, as they can be part of a segmented
        # network but they don't have a segment ID themselves.
        if ignored_service_type:
            service_type_model = SubnetServiceType.db_model
            query = query.filter(~exists().where(and_(
                     cls.db_model.id == service_type_model.subnet_id,
                     service_type_model.service_type == ignored_service_type)))

        # (zigo): When a subnet is created, at this point in the code,
        # its service_types aren't populated in the subnet_service_types
        # object, so the subnet to create isn't filtered by the ~exists
        # above. So we just filter out the subnet to create completely
        # from the result set.
        if subnet_id:
            query = query.filter(cls.db_model.id != subnet_id)

        return [segment_id for (segment_id,) in query.all()]


@base.NeutronObjectRegistry.register
class NetworkSubnetLock(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.NetworkSubnetLock
    primary_keys = ['network_id']

    fields = {
        'network_id': common_types.UUIDField(),
        'subnet_id': common_types.UUIDField(nullable=True)
    }

    @classmethod
    def lock_subnet(cls, context, network_id, subnet_id):
        subnet_lock = super(NetworkSubnetLock, cls).get_object(
            context, network_id=network_id)
        if subnet_lock:
            subnet_lock.subnet_id = subnet_id
            subnet_lock.update()
        else:
            subnet_lock = NetworkSubnetLock(context, network_id=network_id,
                                            subnet_id=subnet_id)
            subnet_lock.create()


@base.NeutronObjectRegistry.register
class SubnetDNSPublishFixedIP(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = dns_models.SubnetDNSPublishFixedIP

    primary_keys = ['subnet_id']

    fields = {
        'subnet_id': common_types.UUIDField(),
        'dns_publish_fixed_ip': obj_fields.BooleanField()
    }
