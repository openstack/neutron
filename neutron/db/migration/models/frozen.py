# Copyright (c) 2014 OpenStack Foundation.
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

"""
The module provides all database models.

Its purpose is to create comparable metadata with current database schema.
Based on this comparison database can be healed with healing migration.

Current HEAD commit is 59da928e945ec58836d34fd561d30a8a446e2728
"""


import sqlalchemy as sa
from sqlalchemy.ext import declarative
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy import schema

from neutron.db import model_base
from neutron.openstack.common import uuidutils


# Dictionary of all tables that was renamed:
# {new_table_name: old_table_name}
renamed_tables = {
    'subnetroutes': 'routes',
    'cisco_credentials': 'credentials',
    'cisco_nexusport_bindings': 'nexusport_bindings',
    'cisco_qos_policies': 'qoss',
    'tz_network_bindings': 'nvp_network_bindings',
    'multi_provider_networks': 'nvp_multi_provider_networks',
    'net_partitions': 'nuage_net_partitions',
    'net_partition_router_mapping': 'nuage_net_partition_router_mapping',
    'router_zone_mapping': 'nuage_router_zone_mapping',
    'subnet_l2dom_mapping': 'nuage_subnet_l2dom_mapping',
    'port_mapping': 'nuage_port_mapping',
    'routerroutes_mapping': 'nuage_routerroutes_mapping',
}

#neutron/plugins/ml2/drivers/mech_arista/db.py
UUID_LEN = 36
STR_LEN = 255

#neutron/plugins/cisco/common/cisco_constants.py
CISCO_CONSTANTS_NETWORK_TYPE_VLAN = 'vlan'
CISCO_CONSTANTS_NETWORK_TYPE_OVERLAY = 'overlay'
CISCO_CONSTANTS_NETWORK_TYPE_TRUNK = 'trunk'
CISCO_CONSTANTS_NETWORK_TYPE_MULTI_SEGMENT = 'multi-segment'
CISCO_CONSTANTS_NETWORK = 'network'
CISCO_CONSTANTS_POLICY = 'policy'
CISCO_CONSTANTS_TENANT_ID_NOT_SET = 'TENANT_ID_NOT_SET'

#neutron/plugins/ml2/models.py
BINDING_PROFILE_LEN = 4095

#neutron/extensions/portbindings.py
VNIC_NORMAL = 'normal'

#neutron/common/constants.py
IPV6_SLAAC = 'slaac'
DHCPV6_STATEFUL = 'dhcpv6-stateful'
DHCPV6_STATELESS = 'dhcpv6-stateless'


BASEV2 = declarative.declarative_base(cls=model_base.NeutronBaseV2)


#neutron/db/models_v2.py
class HasTenant(object):
    tenant_id = sa.Column(sa.String(255))


#neutron/db/models_v2.py
class HasId(object):
    id = sa.Column(sa.String(36),
                   primary_key=True,
                   default=uuidutils.generate_uuid)


#neutron/db/models_v2.py
class HasStatusDescription(object):
    status = sa.Column(sa.String(16), nullable=False)
    status_description = sa.Column(sa.String(255))


#neutron/db/models_v2.py
class IPAvailabilityRange(BASEV2):
    allocation_pool_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('ipallocationpools.id',
                                                 ondelete="CASCADE"),
                                   nullable=False,
                                   primary_key=True)
    first_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)
    last_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)


#neutron/db/models_v2.py
class IPAllocationPool(BASEV2, HasId):
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id',
                                                       ondelete="CASCADE"),
                          nullable=True)
    first_ip = sa.Column(sa.String(64), nullable=False)
    last_ip = sa.Column(sa.String(64), nullable=False)
    available_ranges = orm.relationship(IPAvailabilityRange,
                                        backref='ipallocationpool',
                                        lazy="joined",
                                        cascade='all, delete-orphan')


#neutron/db/models_v2.py
class IPAllocation(BASEV2):
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                     ondelete="CASCADE"),
                        nullable=True)
    ip_address = sa.Column(sa.String(64), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id',
                                                       ondelete="CASCADE"),
                          nullable=False, primary_key=True)
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id",
                                                        ondelete="CASCADE"),
                           nullable=False, primary_key=True)


#neutron/db/models_v2.py
class Route(object):
    destination = sa.Column(sa.String(64), nullable=False, primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


#neutron/db/models_v2.py
class SubnetRoute(BASEV2, Route):
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


#neutron/db/models_v2.py
class Port(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)
    fixed_ips = orm.relationship(IPAllocation, backref='ports', lazy='joined')
    mac_address = sa.Column(sa.String(32), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    device_id = sa.Column(sa.String(255), nullable=False)
    device_owner = sa.Column(sa.String(255), nullable=False)


#neutron/db/models_v2.py
class DNSNameServer(BASEV2):
    address = sa.Column(sa.String(128), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


#neutron/db/models_v2.py
class Subnet(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'))
    ip_version = sa.Column(sa.Integer, nullable=False)
    cidr = sa.Column(sa.String(64), nullable=False)
    gateway_ip = sa.Column(sa.String(64))
    allocation_pools = orm.relationship(IPAllocationPool,
                                        backref='subnet',
                                        lazy="joined",
                                        cascade='delete')
    enable_dhcp = sa.Column(sa.Boolean())
    dns_nameservers = orm.relationship(DNSNameServer,
                                       backref='subnet',
                                       cascade='all, delete, delete-orphan')
    routes = orm.relationship(SubnetRoute,
                              backref='subnet',
                              cascade='all, delete, delete-orphan')
    shared = sa.Column(sa.Boolean)
    ipv6_ra_mode = sa.Column(sa.Enum(IPV6_SLAAC,
                                     DHCPV6_STATEFUL,
                                     DHCPV6_STATELESS,
                                     name='ipv6_ra_modes'), nullable=True)
    ipv6_address_mode = sa.Column(sa.Enum(IPV6_SLAAC,
                                          DHCPV6_STATEFUL,
                                          DHCPV6_STATELESS,
                                          name='ipv6_address_modes'),
                                  nullable=True)


#neutron/db/models_v2.py
class Network(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='networks')
    subnets = orm.relationship(Subnet, backref='networks',
                               lazy="joined")
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    shared = sa.Column(sa.Boolean)


#neutron/db/agents_db.py
class Agent(BASEV2, HasId):
    __table_args__ = (
        sa.UniqueConstraint('agent_type', 'host',
                            name='uniq_agents0agent_type0host'),
    )

    agent_type = sa.Column(sa.String(255), nullable=False)
    binary = sa.Column(sa.String(255), nullable=False)
    topic = sa.Column(sa.String(255), nullable=False)
    host = sa.Column(sa.String(255), nullable=False)
    admin_state_up = sa.Column(sa.Boolean, default=True,
                               server_default=sa.sql.true(), nullable=False)
    created_at = sa.Column(sa.DateTime, nullable=False)
    started_at = sa.Column(sa.DateTime, nullable=False)
    heartbeat_timestamp = sa.Column(sa.DateTime, nullable=False)
    description = sa.Column(sa.String(255))
    configurations = sa.Column(sa.String(4095), nullable=False)


#neutron/db/agentschedulers_db.py
class NetworkDhcpAgentBinding(BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete='CASCADE'),
                           primary_key=True)
    dhcp_agent = orm.relation(Agent)
    dhcp_agent_id = sa.Column(sa.String(36),
                              sa.ForeignKey("agents.id",
                                            ondelete='CASCADE'),
                              primary_key=True)


#neutron/db/allowedaddresspairs_db.py
class AllowedAddressPair(BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    mac_address = sa.Column(sa.String(32), nullable=False, primary_key=True)
    ip_address = sa.Column(sa.String(64), nullable=False, primary_key=True)
    port = orm.relationship(
        Port,
        backref=orm.backref("allowed_address_pairs",
                            lazy="joined", cascade="delete"))


#neutron/db/external_net_db.py
class ExternalNetwork(BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network = orm.relationship(
        Network,
        backref=orm.backref("external", lazy='joined',
                            uselist=False, cascade='delete'))


#neutron/db/extradhcpopt_db.py
class ExtraDhcpOpt(BASEV2, HasId):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        nullable=False)
    opt_name = sa.Column(sa.String(64), nullable=False)
    opt_value = sa.Column(sa.String(255), nullable=False)
    __table_args__ = (sa.UniqueConstraint('port_id',
                                          'opt_name',
                                          name='uidx_portid_optname'),
                      BASEV2.__table_args__,)
    ports = orm.relationship(
        Port,
        backref=orm.backref("dhcp_opts", lazy='joined', cascade='delete'))


#neutron/db/l3_db.py
class Router(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    gw_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    gw_port = orm.relationship(Port, lazy='joined')
    enable_snat = sa.Column(sa.Boolean, default=True,
                            server_default=sa.sql.true(), nullable=False)


#neutron/db/l3_db.py
class FloatingIP(BASEV2, HasId, HasTenant):
    floating_ip_address = sa.Column(sa.String(64), nullable=False)
    floating_network_id = sa.Column(sa.String(36), nullable=False)
    floating_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                                 nullable=False)
    fixed_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    fixed_ip_address = sa.Column(sa.String(64))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'))
    last_known_router_id = sa.Column(sa.String(36))
    status = sa.Column(sa.String(16))


#neutron/db/extraroute_db.py
class RouterRoute(BASEV2, Route):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"),
                          primary_key=True)

    router = orm.relationship(Router,
                              backref=orm.backref("route_list",
                                                  lazy='joined',
                                                  cascade='delete'))


#neutron/db/servicetype_db.py
class ProviderResourceAssociation(BASEV2):
    provider_name = sa.Column(sa.String(255),
                              nullable=False, primary_key=True)
    resource_id = sa.Column(sa.String(36), nullable=False, primary_key=True,
                            unique=True)


#neutron/db/firewall/firewall_db.py
class FirewallRule(BASEV2, HasId, HasTenant):
    __tablename__ = 'firewall_rules'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(40))
    ip_version = sa.Column(sa.Integer, nullable=False)
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port_range_min = sa.Column(sa.Integer)
    source_port_range_max = sa.Column(sa.Integer)
    destination_port_range_min = sa.Column(sa.Integer)
    destination_port_range_max = sa.Column(sa.Integer)
    action = sa.Column(sa.Enum('allow', 'deny', name='firewallrules_action'))
    enabled = sa.Column(sa.Boolean)
    position = sa.Column(sa.Integer)


#neutron/db/firewall/firewall_db.py
class Firewall(BASEV2, HasId, HasTenant):
    __tablename__ = 'firewalls'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(16))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)


#neutron/db/firewall/firewall_db.py
class FirewallPolicy(BASEV2, HasId, HasTenant):
    __tablename__ = 'firewall_policies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    firewall_rules = orm.relationship(
        FirewallRule,
        backref=orm.backref('firewall_policies', cascade='all, delete'),
        order_by='FirewallRule.position',
        collection_class=ordering_list('position', count_from=1))
    audited = sa.Column(sa.Boolean)
    firewalls = orm.relationship(Firewall, backref='firewall_policies')


#neutron/db/l3_agentschedulers_db.py
class RouterL3AgentBinding(BASEV2, HasId):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("routers.id", ondelete='CASCADE'))
    l3_agent = orm.relation(Agent)
    l3_agent_id = sa.Column(sa.String(36),
                            sa.ForeignKey("agents.id",
                                          ondelete='CASCADE'))


#neutron/db/loadbalancer/loadbalancer_db.py
class SessionPersistence(BASEV2):
    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey("vips.id"),
                       primary_key=True)
    type = sa.Column(sa.Enum("SOURCE_IP",
                             "HTTP_COOKIE",
                             "APP_COOKIE",
                             name="sesssionpersistences_type"),
                     nullable=False)
    cookie_name = sa.Column(sa.String(1024))


#neutron/db/loadbalancer/loadbalancer_db.py
class PoolStatistics(BASEV2):
    pool_id = sa.Column(sa.String(36), sa.ForeignKey("pools.id"),
                        primary_key=True)
    bytes_in = sa.Column(sa.BigInteger, nullable=False)
    bytes_out = sa.Column(sa.BigInteger, nullable=False)
    active_connections = sa.Column(sa.BigInteger, nullable=False)
    total_connections = sa.Column(sa.BigInteger, nullable=False)


#neutron/db/loadbalancer/loadbalancer_db.py
class Vip(BASEV2, HasId, HasTenant, HasStatusDescription):
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    protocol_port = sa.Column(sa.Integer, nullable=False)
    protocol = sa.Column(sa.Enum("HTTP", "HTTPS", "TCP", name="lb_protocols"),
                         nullable=False)
    pool_id = sa.Column(sa.String(36), nullable=False, unique=True)
    session_persistence = orm.relationship(SessionPersistence,
                                           uselist=False,
                                           backref="vips",
                                           cascade="all, delete-orphan")
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    connection_limit = sa.Column(sa.Integer)
    port = orm.relationship(Port)


#neutron/db/loadbalancer/loadbalancer_db.py
class Member(BASEV2, HasId, HasTenant, HasStatusDescription):
    __table_args__ = (
        sa.schema.UniqueConstraint('pool_id', 'address', 'protocol_port',
                                   name='uniq_member0pool_id0address0port'),
    )
    pool_id = sa.Column(sa.String(36), sa.ForeignKey("pools.id"),
                        nullable=False)
    address = sa.Column(sa.String(64), nullable=False)
    protocol_port = sa.Column(sa.Integer, nullable=False)
    weight = sa.Column(sa.Integer, nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)


#neutron/db/loadbalancer/loadbalancer_db.py
class Pool(BASEV2, HasId, HasTenant, HasStatusDescription):
    vip_id = sa.Column(sa.String(36), sa.ForeignKey("vips.id"))
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    subnet_id = sa.Column(sa.String(36), nullable=False)
    protocol = sa.Column(sa.Enum("HTTP", "HTTPS", "TCP", name="lb_protocols"),
                         nullable=False)
    lb_method = sa.Column(sa.Enum("ROUND_ROBIN",
                                  "LEAST_CONNECTIONS",
                                  "SOURCE_IP",
                                  name="pools_lb_method"),
                          nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    stats = orm.relationship(PoolStatistics,
                             uselist=False,
                             backref="pools",
                             cascade="all, delete-orphan")
    members = orm.relationship(Member, backref="pools",
                               cascade="all, delete-orphan")
    monitors = orm.relationship("PoolMonitorAssociation", backref="pools",
                                cascade="all, delete-orphan")
    vip = orm.relationship(Vip, backref='pool')

    provider = orm.relationship(
        ProviderResourceAssociation,
        uselist=False,
        lazy="joined",
        primaryjoin="Pool.id==ProviderResourceAssociation.resource_id",
        foreign_keys=[ProviderResourceAssociation.resource_id]
    )


#neutron/db/loadbalancer/loadbalancer_db.py
class HealthMonitor(BASEV2, HasId, HasTenant):
    type = sa.Column(sa.Enum("PING", "TCP", "HTTP", "HTTPS",
                             name="healthmontiors_type"),
                     nullable=False)
    delay = sa.Column(sa.Integer, nullable=False)
    timeout = sa.Column(sa.Integer, nullable=False)
    max_retries = sa.Column(sa.Integer, nullable=False)
    http_method = sa.Column(sa.String(16))
    url_path = sa.Column(sa.String(255))
    expected_codes = sa.Column(sa.String(64))
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)

    pools = orm.relationship(
        "PoolMonitorAssociation", backref="healthmonitor",
        cascade="all", lazy="joined"
    )


#neutron/db/loadbalancer/loadbalancer_db.py
class PoolMonitorAssociation(BASEV2, HasStatusDescription):
    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id"),
                        primary_key=True)
    monitor_id = sa.Column(sa.String(36),
                           sa.ForeignKey("healthmonitors.id"),
                           primary_key=True)


#neutron/db/metering/metering_db.py
class MeteringLabelRule(BASEV2, HasId):
    direction = sa.Column(sa.Enum('ingress', 'egress',
                                  name='meteringlabels_direction'))
    remote_ip_prefix = sa.Column(sa.String(64))
    metering_label_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("meteringlabels.id",
                                                ondelete="CASCADE"),
                                  nullable=False)
    excluded = sa.Column(sa.Boolean, default=False,
                         server_default=sa.sql.false())


#neutron/db/metering/metering_db.py
class MeteringLabel(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    rules = orm.relationship(MeteringLabelRule, backref="label",
                             cascade="delete", lazy="joined")
    routers = orm.relationship(
        Router,
        primaryjoin="MeteringLabel.tenant_id==Router.tenant_id",
        foreign_keys='MeteringLabel.tenant_id',
        uselist=True)


#neutron/db/portbindings_db.py
class PortBindingPort(BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False)
    port = orm.relationship(
        Port,
        backref=orm.backref("portbinding",
                            lazy='joined', uselist=False,
                            cascade='delete'))


#neutron/db/portsecurity_db.py
class PortSecurityBinding(BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)
    port = orm.relationship(
        Port,
        backref=orm.backref("port_security", uselist=False,
                            cascade='delete', lazy='joined'))


#neutron/db/portsecurity_db.py
class NetworkSecurityBinding(BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)
    network = orm.relationship(
        Network,
        backref=orm.backref("port_security", uselist=False,
                            cascade='delete', lazy='joined'))


#neutron/db/quota_db.py
class Quota(BASEV2, HasId):
    tenant_id = sa.Column(sa.String(255), index=True)
    resource = sa.Column(sa.String(255))
    limit = sa.Column(sa.Integer)


#neutron/db/routedserviceinsertion_db.py
class ServiceRouterBinding(BASEV2):
    resource_id = sa.Column(sa.String(36),
                            primary_key=True)
    resource_type = sa.Column(sa.String(36),
                              primary_key=True)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id'),
                          nullable=False)


#neutron/db/routerservicetype_db.py
class RouterServiceTypeBinding(BASEV2):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    service_type_id = sa.Column(sa.String(36),
                                nullable=False)


#neutron/db/securitygroups_db.py
class SecurityGroup(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))


#neutron/db/securitygroups_db.py
class SecurityGroupPortBinding(BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("ports.id",
                                      ondelete='CASCADE'),
                        primary_key=True)
    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("securitygroups.id"),
                                  primary_key=True)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load security group bindings
    ports = orm.relationship(
        Port,
        backref=orm.backref("security_groups",
                            lazy='joined', cascade='delete'))


#neutron/db/securitygroups_db.py
class SecurityGroupRule(BASEV2, HasId,
                        HasTenant):
    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("securitygroups.id",
                                                ondelete="CASCADE"),
                                  nullable=False)

    remote_group_id = sa.Column(sa.String(36),
                                sa.ForeignKey("securitygroups.id",
                                              ondelete="CASCADE"),
                                nullable=True)

    direction = sa.Column(sa.Enum('ingress', 'egress',
                                  name='securitygrouprules_direction'))
    ethertype = sa.Column(sa.String(40))
    protocol = sa.Column(sa.String(40))
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    remote_ip_prefix = sa.Column(sa.String(255))
    security_group = orm.relationship(
        SecurityGroup,
        backref=orm.backref('rules', cascade='all,delete'),
        primaryjoin="SecurityGroup.id==SecurityGroupRule.security_group_id")
    source_group = orm.relationship(
        SecurityGroup,
        backref=orm.backref('source_rules', cascade='all,delete'),
        primaryjoin="SecurityGroup.id==SecurityGroupRule.remote_group_id")


#neutron/db/vpn/vpn_db.py
class IPsecPeerCidr(BASEV2):
    cidr = sa.Column(sa.String(32), nullable=False, primary_key=True)
    ipsec_site_connection_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ipsec_site_connections.id',
                      ondelete="CASCADE"),
        primary_key=True)


#neutron/db/vpn/vpn_db.py
class IPsecPolicy(BASEV2, HasId, HasTenant):
    __tablename__ = 'ipsecpolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    transform_protocol = sa.Column(sa.Enum("esp", "ah", "ah-esp",
                                           name="ipsec_transform_protocols"),
                                   nullable=False)
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    encapsulation_mode = sa.Column(sa.Enum("tunnel", "transport",
                                           name="ipsec_encapsulations"),
                                   nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


#neutron/db/vpn/vpn_db.py
class IKEPolicy(BASEV2, HasId, HasTenant):
    __tablename__ = 'ikepolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    phase1_negotiation_mode = sa.Column(sa.Enum("main",
                                                name="ike_phase1_mode"),
                                        nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    ike_version = sa.Column(sa.Enum("v1", "v2", name="ike_versions"),
                            nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


#neutron/db/vpn/vpn_db.py
class IPsecSiteConnection(BASEV2,
                          HasId, HasTenant):
    __tablename__ = 'ipsec_site_connections'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    peer_address = sa.Column(sa.String(255), nullable=False)
    peer_id = sa.Column(sa.String(255), nullable=False)
    route_mode = sa.Column(sa.String(8), nullable=False)
    mtu = sa.Column(sa.Integer, nullable=False)
    initiator = sa.Column(sa.Enum("bi-directional", "response-only",
                                  name="vpn_initiators"), nullable=False)
    auth_mode = sa.Column(sa.String(16), nullable=False)
    psk = sa.Column(sa.String(255), nullable=False)
    dpd_action = sa.Column(sa.Enum("hold", "clear",
                                   "restart", "disabled",
                                   "restart-by-peer", name="vpn_dpd_actions"),
                           nullable=False)
    dpd_interval = sa.Column(sa.Integer, nullable=False)
    dpd_timeout = sa.Column(sa.Integer, nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    vpnservice_id = sa.Column(sa.String(36),
                              sa.ForeignKey('vpnservices.id'),
                              nullable=False)
    ipsecpolicy_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ipsecpolicies.id'),
                               nullable=False)
    ikepolicy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('ikepolicies.id'),
                             nullable=False)
    ipsecpolicy = orm.relationship(
        IPsecPolicy, backref='ipsec_site_connection')
    ikepolicy = orm.relationship(IKEPolicy, backref='ipsec_site_connection')
    peer_cidrs = orm.relationship(IPsecPeerCidr,
                                  backref='ipsec_site_connection',
                                  lazy='joined',
                                  cascade='all, delete, delete-orphan')


#neutron/db/vpn/vpn_db.py
class VPNService(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=False)
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'),
                          nullable=False)
    subnet = orm.relationship(Subnet)
    router = orm.relationship(Router)
    ipsec_site_connections = orm.relationship(
        IPsecSiteConnection,
        backref='vpnservice',
        cascade="all, delete-orphan")


#neutron/plugins/bigswitch/db/consistency_db.py
class ConsistencyHash(BASEV2):
    __tablename__ = 'consistencyhashes'
    hash_id = sa.Column(sa.String(255),
                        primary_key=True)
    hash = sa.Column(sa.String(255), nullable=False)


#neutron/plugins/bigswitch/routerrule_db.py
class RouterRule(BASEV2):
    id = sa.Column(sa.Integer, primary_key=True)
    source = sa.Column(sa.String(64), nullable=False)
    destination = sa.Column(sa.String(64), nullable=False)
    nexthops = orm.relationship('NextHop', cascade='all,delete')
    action = sa.Column(sa.String(10), nullable=False)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"))


#neutron/plugins/bigswitch/routerrule_db.py
class NextHop(BASEV2):
    rule_id = sa.Column(sa.Integer,
                        sa.ForeignKey('routerrules.id',
                                      ondelete="CASCADE"),
                        primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


#neutron/plugins/brocade/db/models.py
class BrocadeNetwork(BASEV2, HasId):
    vlan = sa.Column(sa.String(10))


#neutron/plugins/brocade/db/models.py
class BrocadePort(BASEV2):
    port_id = sa.Column(sa.String(36), primary_key=True, default="",
                        server_default='')
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("brocadenetworks.id"),
                           nullable=False)
    admin_state_up = sa.Column(sa.Boolean, nullable=False)
    physical_interface = sa.Column(sa.String(36))
    vlan_id = sa.Column(sa.String(36))
    tenant_id = sa.Column(sa.String(36))


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kvVlanAllocation(BASEV2):
    __tablename__ = 'cisco_n1kv_vlan_allocations'

    physical_network = sa.Column(sa.String(64),
                                 nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sa.sql.false())
    network_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('cisco_network_profiles.id',
                                                 ondelete="CASCADE"),
                                   nullable=False)


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kvVxlanAllocation(BASEV2):
    __tablename__ = 'cisco_n1kv_vxlan_allocations'

    vxlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                         autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sa.sql.false())
    network_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('cisco_network_profiles.id',
                                                 ondelete="CASCADE"),
                                   nullable=False)


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kvPortBinding(BASEV2):
    __tablename__ = 'cisco_n1kv_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_policy_profiles.id'))


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kvNetworkBinding(BASEV2):
    __tablename__ = 'cisco_n1kv_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)
    multicast_ip = sa.Column(sa.String(32))
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_network_profiles.id'))


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kVmNetwork(BASEV2):
    __tablename__ = 'cisco_n1kv_vmnetworks'

    name = sa.Column(sa.String(80), primary_key=True)
    profile_id = sa.Column(sa.String(36),
                           sa.ForeignKey('cisco_policy_profiles.id'))
    network_id = sa.Column(sa.String(36))
    port_count = sa.Column(sa.Integer)


#neutron/plugins/cisco/db/n1kv_models_v2.py
class NetworkProfile(BASEV2, HasId):
    __tablename__ = 'cisco_network_profiles'

    name = sa.Column(sa.String(255))
    segment_type = sa.Column(
        sa.Enum(CISCO_CONSTANTS_NETWORK_TYPE_VLAN,
                CISCO_CONSTANTS_NETWORK_TYPE_OVERLAY,
                CISCO_CONSTANTS_NETWORK_TYPE_TRUNK,
                CISCO_CONSTANTS_NETWORK_TYPE_MULTI_SEGMENT,
                name='segment_type'),
        nullable=False)
    sub_type = sa.Column(sa.String(255))
    segment_range = sa.Column(sa.String(255))
    multicast_ip_index = sa.Column(sa.Integer, default=0,
                                   server_default='0')
    multicast_ip_range = sa.Column(sa.String(255))
    physical_network = sa.Column(sa.String(255))


#neutron/plugins/cisco/db/n1kv_models_v2.py
class PolicyProfile(BASEV2):
    __tablename__ = 'cisco_policy_profiles'

    id = sa.Column(sa.String(36), primary_key=True)
    name = sa.Column(sa.String(255))


#neutron/plugins/cisco/db/n1kv_models_v2.py
class ProfileBinding(BASEV2):
    __tablename__ = 'cisco_n1kv_profile_bindings'

    profile_type = sa.Column(sa.Enum(CISCO_CONSTANTS_NETWORK,
                                     CISCO_CONSTANTS_POLICY,
                                     name='profile_type'))
    tenant_id = sa.Column(sa.String(36),
                          primary_key=True,
                          default=CISCO_CONSTANTS_TENANT_ID_NOT_SET,
                          server_default=CISCO_CONSTANTS_TENANT_ID_NOT_SET)
    profile_id = sa.Column(sa.String(36), primary_key=True)


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kvTrunkSegmentBinding(BASEV2):
    __tablename__ = 'cisco_n1kv_trunk_segments'

    trunk_segment_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('networks.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    segment_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    dot1qtag = sa.Column(sa.String(36), nullable=False, primary_key=True)


#neutron/plugins/cisco/db/n1kv_models_v2.py
class N1kvMultiSegmentNetworkBinding(BASEV2):
    __tablename__ = 'cisco_n1kv_multi_segments'

    multi_segment_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('networks.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    segment1_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    segment2_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    encap_profile_name = sa.Column(sa.String(36))


#neutron/plugins/cisco/db/network_models_v2.py
class QoS(BASEV2):
    __tablename__ = 'cisco_qos_policies'

    qos_id = sa.Column(sa.String(255))
    tenant_id = sa.Column(sa.String(255), primary_key=True)
    qos_name = sa.Column(sa.String(255), primary_key=True)
    qos_desc = sa.Column(sa.String(255))


#neutron/plugins/cisco/db/network_models_v2.py
class Credential(BASEV2):
    __tablename__ = 'cisco_credentials'

    credential_id = sa.Column(sa.String(255))
    credential_name = sa.Column(sa.String(255), primary_key=True)
    user_name = sa.Column(sa.String(255))
    password = sa.Column(sa.String(255))
    type = sa.Column(sa.String(255))


#neutron/plugins/cisco/db/network_models_v2.py
class ProviderNetwork(BASEV2):
    __tablename__ = 'cisco_provider_networks'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(255), nullable=False)
    segmentation_id = sa.Column(sa.Integer, nullable=False)


#neutron/plugins/cisco/db/nexus_models_v2.py
#class was renamed from NexusPortBinding to CiscoNexusPortBinding
class CiscoNexusPortBinding(BASEV2):
    __tablename__ = "cisco_nexusport_bindings"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    port_id = sa.Column(sa.String(255))
    vlan_id = sa.Column(sa.Integer, nullable=False)
    switch_ip = sa.Column(sa.String(255), nullable=False)
    instance_id = sa.Column(sa.String(255), nullable=False)


#neutron/plugins/hyperv/model.py
#class was renamed from VlanAllocation to HyperVVlanAllocation
class HyperVVlanAllocation(BASEV2):
    __tablename__ = 'hyperv_vlan_allocations'

    physical_network = sa.Column(sa.String(64),
                                 nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)


#neutron/plugins/hyperv/model.py
#class was renamed from NetworkBinding to HyperVNetworkBinding
class HyperVNetworkBinding(BASEV2):
    __tablename__ = 'hyperv_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)


#neutron/plugins/linuxbridge/db/l2network_models_v2.py
class NetworkState(BASEV2):
    __tablename__ = 'network_states'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)


#neutron/plugins/linuxbridge/db/l2network_models_v2.py
class NetworkBinding(BASEV2):
    __tablename__ = 'network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    physical_network = sa.Column(sa.String(64))
    vlan_id = sa.Column(sa.Integer, nullable=False)


#neutron/plugins/metaplugin/meta_models_v2.py
class NetworkFlavor(BASEV2):
    flavor = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id',
                                                        ondelete="CASCADE"),
                           primary_key=True)


#neutron/plugins/metaplugin/meta_models_v2.py
class RouterFlavor(BASEV2):
    flavor = sa.Column(sa.String(255))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id',
                                                       ondelete="CASCADE"),
                          primary_key=True)


#neutron/plugins/ml2/drivers/brocade/db/models.py
class ML2_BrocadeNetwork(BASEV2, HasId,
                         HasTenant):
    vlan = sa.Column(sa.String(10))
    segment_id = sa.Column(sa.String(36))
    network_type = sa.Column(sa.String(10))


#neutron/plugins/ml2/drivers/brocade/db/models.py
class ML2_BrocadePort(BASEV2, HasId,
                      HasTenant):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("ml2_brocadenetworks.id"),
                           nullable=False)
    admin_state_up = sa.Column(sa.Boolean, nullable=False)
    physical_interface = sa.Column(sa.String(36))
    vlan_id = sa.Column(sa.String(36))


#neutron/plugins/ml2/drivers/cisco/apic/apic_model.py
class NetworkEPG(BASEV2):
    __tablename__ = 'cisco_ml2_apic_epgs'

    network_id = sa.Column(sa.String(255), nullable=False, primary_key=True)
    epg_id = sa.Column(sa.String(64), nullable=False)
    segmentation_id = sa.Column(sa.String(64), nullable=False)
    provider = sa.Column(sa.Boolean, default=False,
                         server_default=sa.sql.false(), nullable=False)


#neutron/plugins/ml2/drivers/cisco/apic/apic_model.py
class PortProfile(BASEV2):
    __tablename__ = 'cisco_ml2_apic_port_profiles'

    node_id = sa.Column(sa.String(255), nullable=False, primary_key=True)
    profile_id = sa.Column(sa.String(64), nullable=False)
    hpselc_id = sa.Column(sa.String(64), nullable=False)
    module = sa.Column(sa.String(10), nullable=False)
    from_port = sa.Column(sa.Integer(), nullable=False)
    to_port = sa.Column(sa.Integer(), nullable=False)


#neutron/plugins/ml2/drivers/cisco/apic/apic_model.py
class TenantContract(BASEV2, HasTenant):
    __tablename__ = 'cisco_ml2_apic_contracts'

    __table_args__ = (sa.PrimaryKeyConstraint('tenant_id'),)
    contract_id = sa.Column(sa.String(64), nullable=False)
    filter_id = sa.Column(sa.String(64), nullable=False)


#neutron/plugins/ml2/drivers/cisco/nexus/nexus_models_v2.py
#class was renamed from NexusPortBinding to CiscoMl2NexusPortBinding
class CiscoMl2NexusPortBinding(BASEV2):
    __tablename__ = "cisco_ml2_nexusport_bindings"

    binding_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    port_id = sa.Column(sa.String(255))
    vlan_id = sa.Column(sa.Integer, nullable=False)
    switch_ip = sa.Column(sa.String(255))
    instance_id = sa.Column(sa.String(255))


#neutron/plugins/ml2/drivers/mech_arista/db.py
class AristaProvisionedNets(BASEV2, HasId,
                            HasTenant):
    __tablename__ = 'arista_provisioned_nets'

    network_id = sa.Column(sa.String(UUID_LEN))
    segmentation_id = sa.Column(sa.Integer)


#neutron/plugins/ml2/drivers/mech_arista/db.py
class AristaProvisionedVms(BASEV2, HasId,
                           HasTenant):
    __tablename__ = 'arista_provisioned_vms'

    vm_id = sa.Column(sa.String(STR_LEN))
    host_id = sa.Column(sa.String(STR_LEN))
    port_id = sa.Column(sa.String(UUID_LEN))
    network_id = sa.Column(sa.String(UUID_LEN))


#neutron/plugins/ml2/drivers/mech_arista/db.py
class AristaProvisionedTenants(BASEV2, HasId,
                               HasTenant):
    __tablename__ = 'arista_provisioned_tenants'


#neutron/plugins/ml2/drivers/type_flat.py
class FlatAllocation(BASEV2):
    __tablename__ = 'ml2_flat_allocations'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)


#neutron/plugins/ml2/drivers/type_gre.py
class GreAllocation(BASEV2):
    __tablename__ = 'ml2_gre_allocations'

    gre_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                       autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sa.sql.false())


#neutron/plugins/ml2/drivers/type_gre.py
class GreEndpoints(BASEV2):
    __tablename__ = 'ml2_gre_endpoints'

    ip_address = sa.Column(sa.String(64), primary_key=True)


#neutron/plugins/ml2/drivers/type_vlan.py
#class was renamed from VlanAllocation to Ml2VlanAllocation
class Ml2VlanAllocation(BASEV2):
    __tablename__ = 'ml2_vlan_allocations'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)


#neutron/plugins/ml2/drivers/type_vxlan.py
class VxlanAllocation(BASEV2):
    __tablename__ = 'ml2_vxlan_allocations'

    vxlan_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sa.sql.false())


#neutron/plugins/ml2/drivers/type_vxlan.py
class VxlanEndpoints(BASEV2):
    __tablename__ = 'ml2_vxlan_endpoints'

    ip_address = sa.Column(sa.String(64), primary_key=True)
    udp_port = sa.Column(sa.Integer, primary_key=True, nullable=False,
                         autoincrement=False)


#neutron/plugins/ml2/models.py
class NetworkSegment(BASEV2, HasId):
    __tablename__ = 'ml2_network_segments'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)


#neutron/plugins/ml2/models.py
class PortBinding(BASEV2):
    __tablename__ = 'ml2_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False, default='',
                     server_default='')
    vnic_type = sa.Column(sa.String(64), nullable=False,
                          default=VNIC_NORMAL, server_default=VNIC_NORMAL)
    profile = sa.Column(sa.String(BINDING_PROFILE_LEN), nullable=False,
                        default='', server_default='')
    vif_type = sa.Column(sa.String(64), nullable=False)
    vif_details = sa.Column(sa.String(4095), nullable=False, default='',
                            server_default='')
    driver = sa.Column(sa.String(64))
    segment = sa.Column(sa.String(36),
                        sa.ForeignKey('ml2_network_segments.id',
                                      ondelete="SET NULL"))
    port = orm.relationship(
        Port,
        backref=orm.backref("port_binding",
                            lazy='joined', uselist=False,
                            cascade='delete'))


#neutron/plugins/mlnx/db/mlnx_models_v2.py
class SegmentationIdAllocation(BASEV2):
    __tablename__ = 'segmentation_id_allocation'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    segmentation_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                                autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sa.sql.false())


#neutron/plugins/mlnx/db/mlnx_models_v2.py
#class was renamed from NetworkBinding to MlnxNetworkBinding
class MlnxNetworkBinding(BASEV2):
    __tablename__ = 'mlnx_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer, nullable=False)


#neutron/plugins/mlnx/db/mlnx_models_v2.py
class PortProfileBinding(BASEV2):
    __tablename__ = 'port_profile'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    vnic_type = sa.Column(sa.String(32), nullable=False)


#neutron/plugins/nec/db/models.py
class OFCId(object):
    ofc_id = sa.Column(sa.String(255), unique=True, nullable=False)


#neutron/plugins/nec/db/models.py
class NeutronId(object):
    neutron_id = sa.Column(sa.String(36), primary_key=True)


#neutron/plugins/nec/db/models.py
class OFCTenantMapping(BASEV2, NeutronId, OFCId):
    """Represents a Tenant on OpenFlow Network/Controller."""


#neutron/plugins/nec/db/models.py
class OFCNetworkMapping(BASEV2, NeutronId, OFCId):
    """Represents a Network on OpenFlow Network/Controller."""


#neutron/plugins/nec/db/models.py
class OFCPortMapping(BASEV2, NeutronId, OFCId):
    """Represents a Port on OpenFlow Network/Controller."""


#neutron/plugins/nec/db/models.py
class OFCRouterMapping(BASEV2, NeutronId, OFCId):
    """Represents a router on OpenFlow Network/Controller."""


#neutron/plugins/nec/db/models.py
class OFCFilterMapping(BASEV2, NeutronId, OFCId):
    """Represents a Filter on OpenFlow Network/Controller."""


#neutron/plugins/nec/db/models.py
class PortInfo(BASEV2):
    id = sa.Column(sa.String(36),
                   sa.ForeignKey('ports.id', ondelete="CASCADE"),
                   primary_key=True)
    datapath_id = sa.Column(sa.String(36), nullable=False)
    port_no = sa.Column(sa.Integer, nullable=False)
    vlan_id = sa.Column(sa.Integer, nullable=False)
    mac = sa.Column(sa.String(32), nullable=False)
    port = orm.relationship(
        Port,
        backref=orm.backref("portinfo",
                            lazy='joined', uselist=False,
                            cascade='delete'))


#neutron/plugins/nec/db/packetfilter.py
class PacketFilter(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False)
    priority = sa.Column(sa.Integer, nullable=False)
    action = sa.Column(sa.String(16), nullable=False)
    in_port = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        nullable=True)
    src_mac = sa.Column(sa.String(32), nullable=False)
    dst_mac = sa.Column(sa.String(32), nullable=False)
    eth_type = sa.Column(sa.Integer, nullable=False)
    src_cidr = sa.Column(sa.String(64), nullable=False)
    dst_cidr = sa.Column(sa.String(64), nullable=False)
    protocol = sa.Column(sa.String(16), nullable=False)
    src_port = sa.Column(sa.Integer, nullable=False)
    dst_port = sa.Column(sa.Integer, nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)

    network = orm.relationship(
        Network,
        backref=orm.backref('packetfilters', lazy='joined', cascade='delete'),
        uselist=False)
    in_port_ref = orm.relationship(
        Port,
        backref=orm.backref('packetfilters', lazy='joined', cascade='delete'),
        primaryjoin="Port.id==PacketFilter.in_port",
        uselist=False)


#neutron/plugins/nec/db/router.py
class RouterProvider(BASEV2):
    provider = sa.Column(sa.String(255))
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)

    router = orm.relationship(Router, uselist=False,
                              backref=orm.backref('provider', uselist=False,
                                                  lazy='joined',
                                                  cascade='delete'))


#neutron/plugins/nuage/nuage_models.py
class NetPartition(BASEV2, HasId):
    __tablename__ = 'nuage_net_partitions'
    name = sa.Column(sa.String(64))
    l3dom_tmplt_id = sa.Column(sa.String(36))
    l2dom_tmplt_id = sa.Column(sa.String(36))


#neutron/plugins/nuage/nuage_models.py
class NetPartitionRouter(BASEV2):
    __tablename__ = "nuage_net_partition_router_mapping"
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                               ondelete="CASCADE"),
                                 primary_key=True)
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    nuage_router_id = sa.Column(sa.String(36))


#neutron/plugins/nuage/nuage_models.py
class RouterZone(BASEV2):
    __tablename__ = "nuage_router_zone_mapping"
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    nuage_zone_id = sa.Column(sa.String(36))
    nuage_user_id = sa.Column(sa.String(36))
    nuage_group_id = sa.Column(sa.String(36))


#neutron/plugins/nuage/nuage_models.py
class SubnetL2Domain(BASEV2):
    __tablename__ = 'nuage_subnet_l2dom_mapping'
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True)
    net_partition_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('nuage_net_partitions.id',
                                               ondelete="CASCADE"))
    nuage_subnet_id = sa.Column(sa.String(36))
    nuage_l2dom_tmplt_id = sa.Column(sa.String(36))
    nuage_user_id = sa.Column(sa.String(36))
    nuage_group_id = sa.Column(sa.String(36))


#neutron/plugins/nuage/nuage_models.py
class PortVPortMapping(BASEV2):
    __tablename__ = 'nuage_port_mapping'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    nuage_vport_id = sa.Column(sa.String(36))
    nuage_vif_id = sa.Column(sa.String(36))
    static_ip = sa.Column(sa.Boolean())


#neutron/plugins/nuage/nuage_models.py
class RouterRoutesMapping(BASEV2, Route):
    __tablename__ = 'nuage_routerroutes_mapping'
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"),
                          primary_key=True,
                          nullable=False)
    nuage_route_id = sa.Column(sa.String(36))


#neutron/plugins/nuage/nuage_models.py
class FloatingIPPoolMapping(BASEV2):
    __tablename__ = "nuage_floatingip_pool_mapping"
    fip_pool_id = sa.Column(sa.String(36), primary_key=True)
    net_id = sa.Column(sa.String(36),
                       sa.ForeignKey('networks.id', ondelete="CASCADE"))
    router_id = sa.Column(sa.String(36))


#neutron/plugins/nuage/nuage_models.py
class FloatingIPMapping(BASEV2):
    __tablename__ = 'nuage_floatingip_mapping'
    fip_id = sa.Column(sa.String(36),
                       sa.ForeignKey('floatingips.id',
                                     ondelete="CASCADE"),
                       primary_key=True)
    router_id = sa.Column(sa.String(36))
    nuage_fip_id = sa.Column(sa.String(36))


#neutron/plugins/openvswitch/ovs_models_v2.py
#class was renamed from VlanAllocation to OvsVlanAllocation
class OvsVlanAllocation(BASEV2):
    __tablename__ = 'ovs_vlan_allocations'

    physical_network = sa.Column(sa.String(64),
                                 nullable=False,
                                 primary_key=True)
    vlan_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                        autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)


#neutron/plugins/openvswitch/ovs_models_v2.py
class TunnelAllocation(BASEV2):
    __tablename__ = 'ovs_tunnel_allocations'

    tunnel_id = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False)


#neutron/plugins/openvswitch/ovs_models_v2.py
#class was renamed from NetworkBinding to OvsNetworkBinding
class OvsNetworkBinding(BASEV2):
    __tablename__ = 'ovs_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    # 'gre', 'vlan', 'flat', 'local'
    network_type = sa.Column(sa.String(32), nullable=False)
    physical_network = sa.Column(sa.String(64))
    segmentation_id = sa.Column(sa.Integer)  # tunnel_id or vlan_id

    network = orm.relationship(
        Network,
        backref=orm.backref("binding", lazy='joined',
                            uselist=False, cascade='delete'))


#neutron/plugins/openvswitch/ovs_models_v2.py
class TunnelEndpoint(BASEV2):
    __tablename__ = 'ovs_tunnel_endpoints'
    __table_args__ = (
        schema.UniqueConstraint('id', name='uniq_ovs_tunnel_endpoints0id'),
        BASEV2.__table_args__,
    )

    ip_address = sa.Column(sa.String(64), primary_key=True)
    id = sa.Column(sa.Integer, nullable=False)


#neutron/plugins/ryu/db/models_v2.py
class TunnelKeyLast(BASEV2):
    last_key = sa.Column(sa.Integer, primary_key=True)


#neutron/plugins/ryu/db/models_v2.py
class TunnelKey(BASEV2):
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)
    tunnel_key = sa.Column(sa.Integer, primary_key=True,
                           nullable=False, autoincrement=False)


#neutron/plugins/vmware/dbexts/lsn_db.py
class LsnPort(BASEV2):
    __tablename__ = 'lsn_port'

    lsn_port_id = sa.Column(sa.String(36), primary_key=True)

    lsn_id = sa.Column(sa.String(36), sa.ForeignKey('lsn.lsn_id',
                                                    ondelete="CASCADE"),
                       nullable=False)
    sub_id = sa.Column(sa.String(36), nullable=False, unique=True)
    mac_addr = sa.Column(sa.String(32), nullable=False, unique=True)


#neutron/plugins/vmware/dbexts/lsn_db.py
class Lsn(BASEV2):
    __tablename__ = 'lsn'

    lsn_id = sa.Column(sa.String(36), primary_key=True)
    net_id = sa.Column(sa.String(36), nullable=False)


#neutron/plugins/vmware/dbexts/maclearning.py
class MacLearningState(BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    mac_learning_enabled = sa.Column(sa.Boolean(), nullable=False)
    port = orm.relationship(
        Port,
        backref=orm.backref("mac_learning_state", lazy='joined',
                            uselist=False, cascade='delete'))


#neutron/plugins/vmware/dbexts/models.py
class TzNetworkBinding(BASEV2):
    __tablename__ = 'tz_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    binding_type = sa.Column(sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                     name='tz_network_bindings_binding_type'),
                             nullable=False, primary_key=True)
    phy_uuid = sa.Column(sa.String(36), primary_key=True, nullable=True)
    vlan_id = sa.Column(sa.Integer, primary_key=True, nullable=True,
                        autoincrement=False)


#neutron/plugins/vmware/dbexts/models.py
class NeutronNsxNetworkMapping(BASEV2):
    __tablename__ = 'neutron_nsx_network_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(36), primary_key=True)


#neutron/plugins/vmware/dbexts/models.py
class NeutronNsxSecurityGroupMapping(BASEV2):
    __tablename__ = 'neutron_nsx_security_group_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('securitygroups.id',
                                         ondelete="CASCADE"),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(36), primary_key=True)


#neutron/plugins/vmware/dbexts/models.py
class NeutronNsxPortMapping(BASEV2):
    __tablename__ = 'neutron_nsx_port_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('ports.id', ondelete="CASCADE"),
                           primary_key=True)
    nsx_switch_id = sa.Column(sa.String(36))
    nsx_port_id = sa.Column(sa.String(36), nullable=False)


#neutron/plugins/vmware/dbexts/models.py
class NeutronNsxRouterMapping(BASEV2):
    __tablename__ = 'neutron_nsx_router_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('routers.id', ondelete='CASCADE'),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(36))


#neutron/plugins/vmware/dbexts/models.py
class MultiProviderNetworks(BASEV2):
    __tablename__ = 'multi_provider_networks'
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)


#neutron/plugins/vmware/dbexts/models.py
class NSXRouterExtAttributes(BASEV2):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    distributed = sa.Column(sa.Boolean, default=False,
                            server_default=sa.sql.false(), nullable=False)
    service_router = sa.Column(sa.Boolean, default=False,
                               server_default=sa.sql.false(), nullable=False)
    router = orm.relationship(
        Router,
        backref=orm.backref("nsx_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


#neutron/plugins/vmware/dbexts/networkgw_db.py
class NetworkConnection(BASEV2, HasTenant):
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'))
    segmentation_type = sa.Column(
        sa.Enum('flat', 'vlan',
                name='networkconnections_segmentation_type'))
    segmentation_id = sa.Column(sa.Integer)
    __table_args__ = (sa.UniqueConstraint(network_gateway_id,
                                          segmentation_type,
                                          segmentation_id),)
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        primary_key=True)


#neutron/plugins/vmware/dbexts/networkgw_db.py
class NetworkGatewayDeviceReference(BASEV2):
    id = sa.Column(sa.String(36), primary_key=True)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'),
                                   primary_key=True)
    interface_name = sa.Column(sa.String(64), primary_key=True)


#neutron/plugins/vmware/dbexts/networkgw_db.py
class NetworkGatewayDevice(BASEV2, HasId,
                           HasTenant):
    nsx_id = sa.Column(sa.String(36))
    # Optional name for the gateway device
    name = sa.Column(sa.String(255))
    # Transport connector type. Not using enum as range of
    # connector types might vary with backend version
    connector_type = sa.Column(sa.String(10))
    # Transport connector IP Address
    connector_ip = sa.Column(sa.String(64))
    # operational status
    status = sa.Column(sa.String(16))


#neutron/plugins/vmware/dbexts/networkgw_db.py
class NetworkGateway(BASEV2, HasId,
                     HasTenant):
    name = sa.Column(sa.String(255))
    # Tenant id is nullable for this resource
    tenant_id = sa.Column(sa.String(36))
    default = sa.Column(sa.Boolean())
    devices = orm.relationship(NetworkGatewayDeviceReference,
                               backref='networkgateways',
                               cascade='all,delete')
    network_connections = orm.relationship(NetworkConnection, lazy='joined')


#neutron/plugins/vmware/dbexts/qos_db.py
class QoSQueue(BASEV2, HasId, HasTenant):
    name = sa.Column(sa.String(255))
    default = sa.Column(sa.Boolean, default=False,
                        server_default=sa.sql.false())
    min = sa.Column(sa.Integer, nullable=False)
    max = sa.Column(sa.Integer, nullable=True)
    qos_marking = sa.Column(sa.Enum('untrusted', 'trusted',
                                    name='qosqueues_qos_marking'))
    dscp = sa.Column(sa.Integer)


#neutron/plugins/vmware/dbexts/qos_db.py
class PortQueueMapping(BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("ports.id", ondelete="CASCADE"),
                        primary_key=True)

    queue_id = sa.Column(sa.String(36), sa.ForeignKey("qosqueues.id"),
                         primary_key=True)

    # Add a relationship to the Port model adding a backref which will
    # allow SQLAlchemy for eagerly load the queue binding
    port = orm.relationship(
        Port,
        backref=orm.backref("qos_queue", uselist=False,
                            cascade='delete', lazy='joined'))


#neutron/plugins/vmware/dbexts/qos_db.py
class NetworkQueueMapping(BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           primary_key=True)

    queue_id = sa.Column(sa.String(36), sa.ForeignKey("qosqueues.id",
                                                      ondelete="CASCADE"))

    # Add a relationship to the Network model adding a backref which will
    # allow SQLAlcremy for eagerly load the queue binding
    network = orm.relationship(
        Network,
        backref=orm.backref("qos_queue", uselist=False,
                            cascade='delete', lazy='joined'))


#neutron/plugins/vmware/dbexts/vcns_models.py
class VcnsRouterBinding(BASEV2, HasStatusDescription):
    __tablename__ = 'vcns_router_bindings'

    # no sa.ForeignKey to routers.id because for now, a router can be removed
    # from routers when delete_router is executed, but the binding is only
    # removed after the Edge is deleted
    router_id = sa.Column(sa.String(36),
                          primary_key=True)
    edge_id = sa.Column(sa.String(16),
                        nullable=True)
    lswitch_id = sa.Column(sa.String(36),
                           nullable=False)


#neutron/plugins/vmware/dbexts/vcns_models.py
class VcnsEdgeFirewallRuleBinding(BASEV2):
    __tablename__ = 'vcns_firewall_rule_bindings'

    rule_id = sa.Column(sa.String(36),
                        sa.ForeignKey("firewall_rules.id"),
                        primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    rule_vseid = sa.Column(sa.String(36))


#neutron/plugins/vmware/dbexts/vcns_models.py
class VcnsEdgePoolBinding(BASEV2):
    __tablename__ = 'vcns_edge_pool_bindings'

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id", ondelete="CASCADE"),
                        primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    pool_vseid = sa.Column(sa.String(36))


#neutron/plugins/vmware/dbexts/vcns_models.py
class VcnsEdgeVipBinding(BASEV2):
    __tablename__ = 'vcns_edge_vip_bindings'

    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey("vips.id", ondelete="CASCADE"),
                       primary_key=True)
    edge_id = sa.Column(sa.String(36))
    vip_vseid = sa.Column(sa.String(36))
    app_profileid = sa.Column(sa.String(36))


#neutron/plugins/vmware/dbexts/vcns_models.py
class VcnsEdgeMonitorBinding(BASEV2):
    __tablename__ = 'vcns_edge_monitor_bindings'

    monitor_id = sa.Column(sa.String(36),
                           sa.ForeignKey("healthmonitors.id",
                                         ondelete="CASCADE"),
                           primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    monitor_vseid = sa.Column(sa.String(36))


#neutron/services/loadbalancer/agent_scheduler.py
class PoolLoadbalancerAgentBinding(BASEV2):
    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id", ondelete='CASCADE'),
                        primary_key=True)
    agent = orm.relation(Agent)
    agent_id = sa.Column(sa.String(36), sa.ForeignKey("agents.id",
                                                      ondelete='CASCADE'),
                         nullable=False)


#neutron/services/loadbalancer/drivers/embrane/models.py
class PoolPort(BASEV2):
    __tablename__ = 'embrane_pool_port'

    pool_id = sa.Column(sa.String(36), sa.ForeignKey('pools.id'),
                        primary_key=True)
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                        nullable=False)


#neutron/services/vpn/service_drivers/cisco_csr_db.py
class IdentifierMap(BASEV2, HasTenant):
    __tablename__ = 'cisco_csr_identifier_map'

    ipsec_site_conn_id = sa.Column(sa.String(64),
                                   sa.ForeignKey('ipsec_site_connections.id',
                                                 ondelete="CASCADE"),
                                   primary_key=True)
    csr_tunnel_id = sa.Column(sa.Integer, nullable=False)
    csr_ike_policy_id = sa.Column(sa.Integer, nullable=False)
    csr_ipsec_policy_id = sa.Column(sa.Integer, nullable=False)


def get_metadata():
    return BASEV2.metadata
