# Copyright 2012 OpenStack Foundation
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

import netaddr
from oslo_log import log as logging
from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions as lib_exc

from neutron.tests.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import exceptions
import neutron.tests.tempest.test

CONF = config.CONF

LOG = logging.getLogger(__name__)


class BaseNetworkTest(neutron.tests.tempest.test.BaseTestCase):

    """
    Base class for the Neutron tests that use the Tempest Neutron REST client

    Per the Neutron API Guide, API v1.x was removed from the source code tree
    (docs.openstack.org/api/openstack-network/2.0/content/Overview-d1e71.html)
    Therefore, v2.x of the Neutron API is assumed. It is also assumed that the
    following options are defined in the [network] section of etc/tempest.conf:

        tenant_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant networks

        tenant_network_mask_bits with the mask bits to be used to partition the
        block defined by tenant-network_cidr

    Finally, it is assumed that the following option is defined in the
    [service_available] section of etc/tempest.conf

        neutron as True
    """

    force_tenant_isolation = False

    # Default to ipv4.
    _ip_version = 4

    @classmethod
    def resource_setup(cls):
        # Create no network resources for these test.
        cls.set_network_resources()
        super(BaseNetworkTest, cls).resource_setup()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")
        if cls._ip_version == 6 and not CONF.network_feature_enabled.ipv6:
            raise cls.skipException("IPv6 Tests are disabled.")

        os = cls.get_client_manager()

        cls.network_cfg = CONF.network
        cls.client = os.network_client
        cls.networks = []
        cls.shared_networks = []
        cls.subnets = []
        cls.ports = []
        cls.routers = []
        cls.pools = []
        cls.vips = []
        cls.members = []
        cls.health_monitors = []
        cls.vpnservices = []
        cls.ikepolicies = []
        cls.floating_ips = []
        cls.metering_labels = []
        cls.service_profiles = []
        cls.flavors = []
        cls.metering_label_rules = []
        cls.fw_rules = []
        cls.fw_policies = []
        cls.ipsecpolicies = []
        cls.qos_rules = []
        cls.qos_policies = []
        cls.ethertype = "IPv" + str(cls._ip_version)
        cls.address_scopes = []
        cls.admin_address_scopes = []

    @classmethod
    def resource_cleanup(cls):
        if CONF.service_available.neutron:
            # Clean up ipsec policies
            for ipsecpolicy in cls.ipsecpolicies:
                cls._try_delete_resource(cls.client.delete_ipsecpolicy,
                                         ipsecpolicy['id'])
            # Clean up firewall policies
            for fw_policy in cls.fw_policies:
                cls._try_delete_resource(cls.client.delete_firewall_policy,
                                         fw_policy['id'])
            # Clean up firewall rules
            for fw_rule in cls.fw_rules:
                cls._try_delete_resource(cls.client.delete_firewall_rule,
                                         fw_rule['id'])
            # Clean up ike policies
            for ikepolicy in cls.ikepolicies:
                cls._try_delete_resource(cls.client.delete_ikepolicy,
                                         ikepolicy['id'])
            # Clean up vpn services
            for vpnservice in cls.vpnservices:
                cls._try_delete_resource(cls.client.delete_vpnservice,
                                         vpnservice['id'])
            # Clean up QoS rules
            for qos_rule in cls.qos_rules:
                cls._try_delete_resource(cls.admin_client.delete_qos_rule,
                                         qos_rule['id'])
            # Clean up QoS policies
            for qos_policy in cls.qos_policies:
                cls._try_delete_resource(cls.admin_client.delete_qos_policy,
                                         qos_policy['id'])
            # Clean up floating IPs
            for floating_ip in cls.floating_ips:
                cls._try_delete_resource(cls.client.delete_floatingip,
                                         floating_ip['id'])
            # Clean up routers
            for router in cls.routers:
                cls._try_delete_resource(cls.delete_router,
                                         router)

            # Clean up health monitors
            for health_monitor in cls.health_monitors:
                cls._try_delete_resource(cls.client.delete_health_monitor,
                                         health_monitor['id'])
            # Clean up members
            for member in cls.members:
                cls._try_delete_resource(cls.client.delete_member,
                                         member['id'])
            # Clean up vips
            for vip in cls.vips:
                cls._try_delete_resource(cls.client.delete_vip,
                                         vip['id'])
            # Clean up pools
            for pool in cls.pools:
                cls._try_delete_resource(cls.client.delete_pool,
                                         pool['id'])
            # Clean up metering label rules
            for metering_label_rule in cls.metering_label_rules:
                cls._try_delete_resource(
                    cls.admin_client.delete_metering_label_rule,
                    metering_label_rule['id'])
            # Clean up metering labels
            for metering_label in cls.metering_labels:
                cls._try_delete_resource(
                    cls.admin_client.delete_metering_label,
                    metering_label['id'])
            # Clean up flavors
            for flavor in cls.flavors:
                cls._try_delete_resource(
                    cls.admin_client.delete_flavor,
                    flavor['id'])
            # Clean up service profiles
            for service_profile in cls.service_profiles:
                cls._try_delete_resource(
                    cls.admin_client.delete_service_profile,
                    service_profile['id'])
            # Clean up ports
            for port in cls.ports:
                cls._try_delete_resource(cls.client.delete_port,
                                         port['id'])
            # Clean up subnets
            for subnet in cls.subnets:
                cls._try_delete_resource(cls.client.delete_subnet,
                                         subnet['id'])
            # Clean up networks
            for network in cls.networks:
                cls._try_delete_resource(cls.client.delete_network,
                                         network['id'])

            # Clean up shared networks
            for network in cls.shared_networks:
                cls._try_delete_resource(cls.admin_client.delete_network,
                                         network['id'])

            for address_scope in cls.address_scopes:
                cls._try_delete_resource(cls.client.delete_address_scope,
                                         address_scope['id'])

            for address_scope in cls.admin_address_scopes:
                cls._try_delete_resource(
                    cls.admin_client.delete_address_scope,
                    address_scope['id'])

            cls.clear_isolated_creds()
        super(BaseNetworkTest, cls).resource_cleanup()

    @classmethod
    def _try_delete_resource(self, delete_callable, *args, **kwargs):
        """Cleanup resources in case of test-failure

        Some resources are explicitly deleted by the test.
        If the test failed to delete a resource, this method will execute
        the appropriate delete methods. Otherwise, the method ignores NotFound
        exceptions thrown for resources that were correctly deleted by the
        test.

        :param delete_callable: delete method
        :param args: arguments for delete method
        :param kwargs: keyword arguments for delete method
        """
        try:
            delete_callable(*args, **kwargs)
        # if resource is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    @classmethod
    def create_network(cls, network_name=None, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network-')

        body = cls.client.create_network(name=network_name, **kwargs)
        network = body['network']
        cls.networks.append(network)
        return network

    @classmethod
    def create_shared_network(cls, network_name=None, **post_body):
        network_name = network_name or data_utils.rand_name('sharednetwork-')
        post_body.update({'name': network_name, 'shared': True})
        body = cls.admin_client.create_network(**post_body)
        network = body['network']
        cls.shared_networks.append(network)
        return network

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):
        """Wrapper utility that returns a test subnet."""

        # allow tests to use admin client
        if not client:
            client = cls.client

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else cls._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or netaddr.IPNetwork(CONF.network.tenant_network_cidr)
            mask_bits = mask_bits or CONF.network.tenant_network_mask_bits
        elif ip_version == 6:
            cidr = (
                cidr or netaddr.IPNetwork(CONF.network.tenant_network_v6_cidr))
            mask_bits = mask_bits or CONF.network.tenant_network_v6_mask_bits
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(netaddr.IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                body = client.create_subnet(
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=ip_version,
                    gateway_ip=gateway_ip,
                    **kwargs)
                break
            except lib_exc.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise exceptions.BuildErrorException(message)
        subnet = body['subnet']
        cls.subnets.append(subnet)
        return subnet

    @classmethod
    def create_port(cls, network, **kwargs):
        """Wrapper utility that returns a test port."""
        body = cls.client.create_port(network_id=network['id'],
                                      **kwargs)
        port = body['port']
        cls.ports.append(port)
        return port

    @classmethod
    def update_port(cls, port, **kwargs):
        """Wrapper utility that updates a test port."""
        body = cls.client.update_port(port['id'],
                                      **kwargs)
        return body['port']

    @classmethod
    def create_router(cls, router_name=None, admin_state_up=False,
                      external_network_id=None, enable_snat=None,
                      **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat:
            ext_gw_info['enable_snat'] = enable_snat
        body = cls.client.create_router(
            router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        cls.routers.append(router)
        return router

    @classmethod
    def create_floatingip(cls, external_network_id):
        """Wrapper utility that returns a test floating IP."""
        body = cls.client.create_floatingip(
            floating_network_id=external_network_id)
        fip = body['floatingip']
        cls.floating_ips.append(fip)
        return fip

    @classmethod
    def create_pool(cls, name, lb_method, protocol, subnet):
        """Wrapper utility that returns a test pool."""
        body = cls.client.create_pool(
            name=name,
            lb_method=lb_method,
            protocol=protocol,
            subnet_id=subnet['id'])
        pool = body['pool']
        cls.pools.append(pool)
        return pool

    @classmethod
    def update_pool(cls, name):
        """Wrapper utility that returns a test pool."""
        body = cls.client.update_pool(name=name)
        pool = body['pool']
        return pool

    @classmethod
    def create_vip(cls, name, protocol, protocol_port, subnet, pool):
        """Wrapper utility that returns a test vip."""
        body = cls.client.create_vip(name=name,
                                     protocol=protocol,
                                     protocol_port=protocol_port,
                                     subnet_id=subnet['id'],
                                     pool_id=pool['id'])
        vip = body['vip']
        cls.vips.append(vip)
        return vip

    @classmethod
    def update_vip(cls, name):
        body = cls.client.update_vip(name=name)
        vip = body['vip']
        return vip

    @classmethod
    def create_member(cls, protocol_port, pool, ip_version=None):
        """Wrapper utility that returns a test member."""
        ip_version = ip_version if ip_version is not None else cls._ip_version
        member_address = "fd00::abcd" if ip_version == 6 else "10.0.9.46"
        body = cls.client.create_member(address=member_address,
                                        protocol_port=protocol_port,
                                        pool_id=pool['id'])
        member = body['member']
        cls.members.append(member)
        return member

    @classmethod
    def update_member(cls, admin_state_up):
        body = cls.client.update_member(admin_state_up=admin_state_up)
        member = body['member']
        return member

    @classmethod
    def create_health_monitor(cls, delay, max_retries, Type, timeout):
        """Wrapper utility that returns a test health monitor."""
        body = cls.client.create_health_monitor(delay=delay,
                                                max_retries=max_retries,
                                                type=Type,
                                                timeout=timeout)
        health_monitor = body['health_monitor']
        cls.health_monitors.append(health_monitor)
        return health_monitor

    @classmethod
    def update_health_monitor(cls, admin_state_up):
        body = cls.client.update_vip(admin_state_up=admin_state_up)
        health_monitor = body['health_monitor']
        return health_monitor

    @classmethod
    def create_router_interface(cls, router_id, subnet_id):
        """Wrapper utility that returns a router interface."""
        interface = cls.client.add_router_interface_with_subnet_id(
            router_id, subnet_id)
        return interface

    @classmethod
    def create_vpnservice(cls, subnet_id, router_id):
        """Wrapper utility that returns a test vpn service."""
        body = cls.client.create_vpnservice(
            subnet_id=subnet_id, router_id=router_id, admin_state_up=True,
            name=data_utils.rand_name("vpnservice-"))
        vpnservice = body['vpnservice']
        cls.vpnservices.append(vpnservice)
        return vpnservice

    @classmethod
    def create_ikepolicy(cls, name):
        """Wrapper utility that returns a test ike policy."""
        body = cls.client.create_ikepolicy(name=name)
        ikepolicy = body['ikepolicy']
        cls.ikepolicies.append(ikepolicy)
        return ikepolicy

    @classmethod
    def create_firewall_rule(cls, action, protocol):
        """Wrapper utility that returns a test firewall rule."""
        body = cls.client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action=action,
            protocol=protocol)
        fw_rule = body['firewall_rule']
        cls.fw_rules.append(fw_rule)
        return fw_rule

    @classmethod
    def create_firewall_policy(cls):
        """Wrapper utility that returns a test firewall policy."""
        body = cls.client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy = body['firewall_policy']
        cls.fw_policies.append(fw_policy)
        return fw_policy

    @classmethod
    def create_qos_policy(cls, name, description, shared, tenant_id=None):
        """Wrapper utility that returns a test QoS policy."""
        body = cls.admin_client.create_qos_policy(
            name, description, shared, tenant_id)
        qos_policy = body['policy']
        cls.qos_policies.append(qos_policy)
        return qos_policy

    @classmethod
    def create_qos_bandwidth_limit_rule(cls, policy_id,
                                       max_kbps, max_burst_kbps):
        """Wrapper utility that returns a test QoS bandwidth limit rule."""
        body = cls.admin_client.create_bandwidth_limit_rule(
            policy_id, max_kbps, max_burst_kbps)
        qos_rule = body['bandwidth_limit_rule']
        cls.qos_rules.append(qos_rule)
        return qos_rule

    @classmethod
    def delete_router(cls, router):
        body = cls.client.list_router_interfaces(router['id'])
        interfaces = body['ports']
        for i in interfaces:
            try:
                cls.client.remove_router_interface_with_subnet_id(
                    router['id'], i['fixed_ips'][0]['subnet_id'])
            except lib_exc.NotFound:
                pass
        cls.client.delete_router(router['id'])

    @classmethod
    def create_ipsecpolicy(cls, name):
        """Wrapper utility that returns a test ipsec policy."""
        body = cls.client.create_ipsecpolicy(name=name)
        ipsecpolicy = body['ipsecpolicy']
        cls.ipsecpolicies.append(ipsecpolicy)
        return ipsecpolicy

    @classmethod
    def create_address_scope(cls, name, is_admin=False, **kwargs):
        if is_admin:
            body = cls.admin_client.create_address_scope(name=name, **kwargs)
            cls.admin_address_scopes.append(body['address_scope'])
        else:
            body = cls.client.create_address_scope(name=name, **kwargs)
            cls.address_scopes.append(body['address_scope'])
        return body['address_scope']


class BaseAdminNetworkTest(BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(BaseAdminNetworkTest, cls).resource_setup()

        try:
            creds = cls.isolated_creds.get_admin_creds()
            cls.os_adm = clients.Manager(credentials=creds)
        except NotImplementedError:
            msg = ("Missing Administrative Network API credentials "
                   "in configuration.")
            raise cls.skipException(msg)
        cls.admin_client = cls.os_adm.network_client

    @classmethod
    def create_metering_label(cls, name, description):
        """Wrapper utility that returns a test metering label."""
        body = cls.admin_client.create_metering_label(
            description=description,
            name=data_utils.rand_name("metering-label"))
        metering_label = body['metering_label']
        cls.metering_labels.append(metering_label)
        return metering_label

    @classmethod
    def create_metering_label_rule(cls, remote_ip_prefix, direction,
                                   metering_label_id):
        """Wrapper utility that returns a test metering label rule."""
        body = cls.admin_client.create_metering_label_rule(
            remote_ip_prefix=remote_ip_prefix, direction=direction,
            metering_label_id=metering_label_id)
        metering_label_rule = body['metering_label_rule']
        cls.metering_label_rules.append(metering_label_rule)
        return metering_label_rule

    @classmethod
    def create_flavor(cls, name, description, service_type):
        """Wrapper utility that returns a test flavor."""
        body = cls.admin_client.create_flavor(
            description=description, service_type=service_type,
            name=name)
        flavor = body['flavor']
        cls.flavors.append(flavor)
        return flavor

    @classmethod
    def create_service_profile(cls, description, metainfo, driver):
        """Wrapper utility that returns a test service profile."""
        body = cls.admin_client.create_service_profile(
            driver=driver, metainfo=metainfo, description=description)
        service_profile = body['service_profile']
        cls.service_profiles.append(service_profile)
        return service_profile
