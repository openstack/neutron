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

import functools
import math

import netaddr
from neutron_lib import constants as const
from tempest.common import utils as tutils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.common import constants
from neutron.common import utils
from neutron.tests.tempest.api import clients
from neutron.tests.tempest import config
from neutron.tests.tempest import exceptions

CONF = config.CONF


class BaseNetworkTest(test.BaseTestCase):

    """
    Base class for the Neutron tests that use the Tempest Neutron REST client

    Per the Neutron API Guide, API v1.x was removed from the source code tree
    (docs.openstack.org/api/openstack-network/2.0/content/Overview-d1e71.html)
    Therefore, v2.x of the Neutron API is assumed. It is also assumed that the
    following options are defined in the [network] section of etc/tempest.conf:

        project_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant networks

        project_network_mask_bits with the mask bits to be used to partition
        the block defined by tenant-network_cidr

    Finally, it is assumed that the following option is defined in the
    [service_available] section of etc/tempest.conf

        neutron as True
    """

    force_tenant_isolation = False
    credentials = ['primary']

    # Default to ipv4.
    _ip_version = 4

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = super(BaseNetworkTest, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )
        # Neutron uses a different clients manager than the one in the Tempest
        return clients.Manager(manager.credentials)

    @classmethod
    def skip_checks(cls):
        super(BaseNetworkTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")
        if cls._ip_version == 6 and not CONF.network_feature_enabled.ipv6:
            raise cls.skipException("IPv6 Tests are disabled.")
        for req_ext in getattr(cls, 'required_extensions', []):
            if not tutils.is_extension_enabled(req_ext, 'network'):
                msg = "%s extension not enabled." % req_ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Create no network resources for these test.
        cls.set_network_resources()
        super(BaseNetworkTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(BaseNetworkTest, cls).setup_clients()
        cls.client = cls.os_primary.network_client

    @classmethod
    def resource_setup(cls):
        super(BaseNetworkTest, cls).resource_setup()

        cls.networks = []
        cls.admin_networks = []
        cls.subnets = []
        cls.admin_subnets = []
        cls.ports = []
        cls.routers = []
        cls.floating_ips = []
        cls.metering_labels = []
        cls.service_profiles = []
        cls.flavors = []
        cls.metering_label_rules = []
        cls.qos_rules = []
        cls.qos_policies = []
        cls.ethertype = "IPv" + str(cls._ip_version)
        cls.address_scopes = []
        cls.admin_address_scopes = []
        cls.subnetpools = []
        cls.admin_subnetpools = []
        cls.security_groups = []
        cls.projects = []

    @classmethod
    def resource_cleanup(cls):
        if CONF.service_available.neutron:
            # Clean up floating IPs
            for floating_ip in cls.floating_ips:
                cls._try_delete_resource(cls.client.delete_floatingip,
                                         floating_ip['id'])
            # Clean up routers
            for router in cls.routers:
                cls._try_delete_resource(cls.delete_router,
                                         router)
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
            # Clean up admin subnets
            for subnet in cls.admin_subnets:
                cls._try_delete_resource(cls.admin_client.delete_subnet,
                                         subnet['id'])
            # Clean up networks
            for network in cls.networks:
                cls._try_delete_resource(cls.client.delete_network,
                                         network['id'])

            # Clean up admin networks
            for network in cls.admin_networks:
                cls._try_delete_resource(cls.admin_client.delete_network,
                                         network['id'])

            # Clean up security groups
            for secgroup in cls.security_groups:
                cls._try_delete_resource(cls.client.delete_security_group,
                                         secgroup['id'])

            for subnetpool in cls.subnetpools:
                cls._try_delete_resource(cls.client.delete_subnetpool,
                                         subnetpool['id'])

            for subnetpool in cls.admin_subnetpools:
                cls._try_delete_resource(cls.admin_client.delete_subnetpool,
                                         subnetpool['id'])

            for address_scope in cls.address_scopes:
                cls._try_delete_resource(cls.client.delete_address_scope,
                                         address_scope['id'])

            for address_scope in cls.admin_address_scopes:
                cls._try_delete_resource(
                    cls.admin_client.delete_address_scope,
                    address_scope['id'])

            for project in cls.projects:
                cls._try_delete_resource(
                    cls.identity_admin_client.delete_project,
                    project['id'])

            # Clean up QoS rules
            for qos_rule in cls.qos_rules:
                cls._try_delete_resource(cls.admin_client.delete_qos_rule,
                                         qos_rule['id'])
            # Clean up QoS policies
            # as all networks and ports are already removed, QoS policies
            # shouldn't be "in use"
            for qos_policy in cls.qos_policies:
                cls._try_delete_resource(cls.admin_client.delete_qos_policy,
                                         qos_policy['id'])

        super(BaseNetworkTest, cls).resource_cleanup()

    @classmethod
    def _try_delete_resource(cls, delete_callable, *args, **kwargs):
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
    def create_network(cls, network_name=None, client=None, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network-')

        client = client or cls.client
        body = client.create_network(name=network_name, **kwargs)
        network = body['network']
        if client is cls.client:
            cls.networks.append(network)
        else:
            cls.admin_networks.append(network)
        return network

    @classmethod
    def create_shared_network(cls, network_name=None, **post_body):
        network_name = network_name or data_utils.rand_name('sharednetwork-')
        post_body.update({'name': network_name, 'shared': True})
        body = cls.admin_client.create_network(**post_body)
        network = body['network']
        cls.admin_networks.append(network)
        return network

    @classmethod
    def create_network_keystone_v3(cls, network_name=None, project_id=None,
                                   tenant_id=None, client=None):
        """Wrapper utility that creates a test network with project_id."""
        client = client or cls.client
        network_name = network_name or data_utils.rand_name(
            'test-network-with-project_id')
        project_id = cls.client.tenant_id
        body = client.create_network_keystone_v3(network_name, project_id,
            tenant_id)
        network = body['network']
        if client is cls.client:
            cls.networks.append(network)
        else:
            cls.admin_networks.append(network)
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
            cidr = cidr or netaddr.IPNetwork(
                config.safe_get_config_value(
                    'network', 'project_network_cidr'))
            mask_bits = (
                mask_bits or config.safe_get_config_value(
                    'network', 'project_network_mask_bits'))
        elif ip_version == 6:
            cidr = (
                cidr or netaddr.IPNetwork(
                    config.safe_get_config_value(
                        'network', 'project_network_v6_cidr')))
            mask_bits = (
                mask_bits or config.safe_get_config_value(
                    'network', 'project_network_v6_mask_bits'))
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
            raise ValueError(message)
        subnet = body['subnet']
        if client is cls.client:
            cls.subnets.append(subnet)
        else:
            cls.admin_subnets.append(subnet)
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
    def _create_router_with_client(
        cls, client, router_name=None, admin_state_up=False,
        external_network_id=None, enable_snat=None, **kwargs
    ):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = client.create_router(
            router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        cls.routers.append(router)
        return router

    @classmethod
    def create_router(cls, *args, **kwargs):
        return cls._create_router_with_client(cls.client, *args, **kwargs)

    @classmethod
    def create_admin_router(cls, *args, **kwargs):
        return cls._create_router_with_client(cls.os_admin.network_client,
                                              *args, **kwargs)

    @classmethod
    def create_floatingip(cls, external_network_id):
        """Wrapper utility that returns a test floating IP."""
        body = cls.client.create_floatingip(
            floating_network_id=external_network_id)
        fip = body['floatingip']
        cls.floating_ips.append(fip)
        return fip

    @classmethod
    def create_router_interface(cls, router_id, subnet_id):
        """Wrapper utility that returns a router interface."""
        interface = cls.client.add_router_interface_with_subnet_id(
            router_id, subnet_id)
        return interface

    @classmethod
    def get_supported_qos_rule_types(cls):
        body = cls.client.list_qos_rule_types()
        return [rule_type['type'] for rule_type in body['rule_types']]

    @classmethod
    def create_qos_policy(cls, name, description=None, shared=False,
                          tenant_id=None, is_default=False):
        """Wrapper utility that returns a test QoS policy."""
        body = cls.admin_client.create_qos_policy(
            name, description, shared, tenant_id, is_default)
        qos_policy = body['policy']
        cls.qos_policies.append(qos_policy)
        return qos_policy

    @classmethod
    def create_qos_bandwidth_limit_rule(cls, policy_id, max_kbps,
                                        max_burst_kbps,
                                        direction=const.EGRESS_DIRECTION):
        """Wrapper utility that returns a test QoS bandwidth limit rule."""
        body = cls.admin_client.create_bandwidth_limit_rule(
            policy_id, max_kbps, max_burst_kbps, direction)
        qos_rule = body['bandwidth_limit_rule']
        cls.qos_rules.append(qos_rule)
        return qos_rule

    @classmethod
    def delete_router(cls, router):
        body = cls.client.list_router_interfaces(router['id'])
        interfaces = [port for port in body['ports']
                      if port['device_owner'] in const.ROUTER_INTERFACE_OWNERS]
        for i in interfaces:
            try:
                cls.client.remove_router_interface_with_subnet_id(
                    router['id'], i['fixed_ips'][0]['subnet_id'])
            except lib_exc.NotFound:
                pass
        cls.client.delete_router(router['id'])

    @classmethod
    def create_address_scope(cls, name, is_admin=False, **kwargs):
        if is_admin:
            body = cls.admin_client.create_address_scope(name=name, **kwargs)
            cls.admin_address_scopes.append(body['address_scope'])
        else:
            body = cls.client.create_address_scope(name=name, **kwargs)
            cls.address_scopes.append(body['address_scope'])
        return body['address_scope']

    @classmethod
    def create_subnetpool(cls, name, is_admin=False, **kwargs):
        if is_admin:
            body = cls.admin_client.create_subnetpool(name, **kwargs)
            cls.admin_subnetpools.append(body['subnetpool'])
        else:
            body = cls.client.create_subnetpool(name, **kwargs)
            cls.subnetpools.append(body['subnetpool'])
        return body['subnetpool']

    @classmethod
    def create_project(cls, name=None, description=None):
        test_project = name or data_utils.rand_name('test_project_')
        test_description = description or data_utils.rand_name('desc_')
        project = cls.identity_admin_client.create_project(
            name=test_project,
            description=test_description)['project']
        cls.projects.append(project)
        return project

    @classmethod
    def create_security_group(cls, name, **kwargs):
        body = cls.client.create_security_group(name=name, **kwargs)
        cls.security_groups.append(body['security_group'])
        return body['security_group']


class BaseAdminNetworkTest(BaseNetworkTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(BaseAdminNetworkTest, cls).setup_clients()
        cls.admin_client = cls.os_admin.network_client
        cls.identity_admin_client = cls.os_admin.projects_client

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

    @classmethod
    def get_unused_ip(cls, net_id, ip_version=None):
        """Get an unused ip address in a allocation pool of net"""
        body = cls.admin_client.list_ports(network_id=net_id)
        ports = body['ports']
        used_ips = []
        for port in ports:
            used_ips.extend(
                [fixed_ip['ip_address'] for fixed_ip in port['fixed_ips']])
        body = cls.admin_client.list_subnets(network_id=net_id)
        subnets = body['subnets']

        for subnet in subnets:
            if ip_version and subnet['ip_version'] != ip_version:
                continue
            cidr = subnet['cidr']
            allocation_pools = subnet['allocation_pools']
            iterators = []
            if allocation_pools:
                for allocation_pool in allocation_pools:
                    iterators.append(netaddr.iter_iprange(
                        allocation_pool['start'], allocation_pool['end']))
            else:
                net = netaddr.IPNetwork(cidr)

                def _iterip():
                    for ip in net:
                        if ip not in (net.network, net.broadcast):
                            yield ip
                iterators.append(iter(_iterip()))

            for iterator in iterators:
                for ip in iterator:
                    if str(ip) not in used_ips:
                        return str(ip)

        message = (
            "net(%s) has no usable IP address in allocation pools" % net_id)
        raise exceptions.InvalidConfiguration(message)


def require_qos_rule_type(rule_type):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if rule_type not in self.get_supported_qos_rule_types():
                raise self.skipException(
                    "%s rule type is required." % rule_type)
            return f(self, *func_args, **func_kwargs)
        return wrapper
    return decorator


def _require_sorting(f):
    @functools.wraps(f)
    def inner(self, *args, **kwargs):
        if not tutils.is_extension_enabled("sorting", "network"):
            self.skipTest('Sorting feature is required')
        return f(self, *args, **kwargs)
    return inner


def _require_pagination(f):
    @functools.wraps(f)
    def inner(self, *args, **kwargs):
        if not tutils.is_extension_enabled("pagination", "network"):
            self.skipTest('Pagination feature is required')
        return f(self, *args, **kwargs)
    return inner


class BaseSearchCriteriaTest(BaseNetworkTest):

    # This should be defined by subclasses to reflect resource name to test
    resource = None

    field = 'name'

    # NOTE(ihrachys): some names, like those starting with an underscore (_)
    # are sorted differently depending on whether the plugin implements native
    # sorting support, or not. So we avoid any such cases here, sticking to
    # alphanumeric. Also test a case when there are multiple resources with the
    # same name
    resource_names = ('test1', 'abc1', 'test10', '123test') + ('test1',)

    force_tenant_isolation = True

    list_kwargs = {}

    list_as_admin = False

    def assertSameOrder(self, original, actual):
        # gracefully handle iterators passed
        original = list(original)
        actual = list(actual)
        self.assertEqual(len(original), len(actual))
        for expected, res in zip(original, actual):
            self.assertEqual(expected[self.field], res[self.field])

    @utils.classproperty
    def plural_name(self):
        return '%ss' % self.resource

    @property
    def list_client(self):
        return self.admin_client if self.list_as_admin else self.client

    def list_method(self, *args, **kwargs):
        method = getattr(self.list_client, 'list_%s' % self.plural_name)
        kwargs.update(self.list_kwargs)
        return method(*args, **kwargs)

    def get_bare_url(self, url):
        base_url = self.client.base_url
        self.assertTrue(url.startswith(base_url))
        return url[len(base_url):]

    @classmethod
    def _extract_resources(cls, body):
        return body[cls.plural_name]

    def _test_list_sorts(self, direction):
        sort_args = {
            'sort_dir': direction,
            'sort_key': self.field
        }
        body = self.list_method(**sort_args)
        resources = self._extract_resources(body)
        self.assertNotEmpty(
            resources, "%s list returned is empty" % self.resource)
        retrieved_names = [res[self.field] for res in resources]
        expected = sorted(retrieved_names)
        if direction == constants.SORT_DIRECTION_DESC:
            expected = list(reversed(expected))
        self.assertEqual(expected, retrieved_names)

    @_require_sorting
    def _test_list_sorts_asc(self):
        self._test_list_sorts(constants.SORT_DIRECTION_ASC)

    @_require_sorting
    def _test_list_sorts_desc(self):
        self._test_list_sorts(constants.SORT_DIRECTION_DESC)

    @_require_pagination
    def _test_list_pagination(self):
        for limit in range(1, len(self.resource_names) + 1):
            pagination_args = {
                'limit': limit,
            }
            body = self.list_method(**pagination_args)
            resources = self._extract_resources(body)
            self.assertEqual(limit, len(resources))

    @_require_pagination
    def _test_list_no_pagination_limit_0(self):
        pagination_args = {
            'limit': 0,
        }
        body = self.list_method(**pagination_args)
        resources = self._extract_resources(body)
        self.assertGreaterEqual(len(resources), len(self.resource_names))

    def _test_list_pagination_iteratively(self, lister):
        # first, collect all resources for later comparison
        sort_args = {
            'sort_dir': constants.SORT_DIRECTION_ASC,
            'sort_key': self.field
        }
        body = self.list_method(**sort_args)
        expected_resources = self._extract_resources(body)
        self.assertNotEmpty(expected_resources)

        resources = lister(
            len(expected_resources), sort_args
        )

        # finally, compare that the list retrieved in one go is identical to
        # the one containing pagination results
        self.assertSameOrder(expected_resources, resources)

    def _list_all_with_marker(self, niterations, sort_args):
        # paginate resources one by one, using last fetched resource as a
        # marker
        resources = []
        for i in range(niterations):
            pagination_args = sort_args.copy()
            pagination_args['limit'] = 1
            if resources:
                pagination_args['marker'] = resources[-1]['id']
            body = self.list_method(**pagination_args)
            resources_ = self._extract_resources(body)
            self.assertEqual(1, len(resources_))
            resources.extend(resources_)
        return resources

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_with_marker(self):
        self._test_list_pagination_iteratively(self._list_all_with_marker)

    def _list_all_with_hrefs(self, niterations, sort_args):
        # paginate resources one by one, using next href links
        resources = []
        prev_links = {}

        for i in range(niterations):
            if prev_links:
                uri = self.get_bare_url(prev_links['next'])
            else:
                sort_args.update(self.list_kwargs)
                uri = self.list_client.build_uri(
                    self.plural_name, limit=1, **sort_args)
            prev_links, body = self.list_client.get_uri_with_links(
                self.plural_name, uri
            )
            resources_ = self._extract_resources(body)
            self.assertEqual(1, len(resources_))
            resources.extend(resources_)

        # The last element is empty and does not contain 'next' link
        uri = self.get_bare_url(prev_links['next'])
        prev_links, body = self.client.get_uri_with_links(
            self.plural_name, uri
        )
        self.assertNotIn('next', prev_links)

        # Now walk backwards and compare results
        resources2 = []
        for i in range(niterations):
            uri = self.get_bare_url(prev_links['previous'])
            prev_links, body = self.list_client.get_uri_with_links(
                self.plural_name, uri
            )
            resources_ = self._extract_resources(body)
            self.assertEqual(1, len(resources_))
            resources2.extend(resources_)

        self.assertSameOrder(resources, reversed(resources2))

        return resources

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_with_href_links(self):
        self._test_list_pagination_iteratively(self._list_all_with_hrefs)

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_page_reverse_with_href_links(
            self, direction=constants.SORT_DIRECTION_ASC):
        pagination_args = {
            'sort_dir': direction,
            'sort_key': self.field,
        }
        body = self.list_method(**pagination_args)
        expected_resources = self._extract_resources(body)

        page_size = 2
        pagination_args['limit'] = page_size

        prev_links = {}
        resources = []
        num_resources = len(expected_resources)
        niterations = int(math.ceil(float(num_resources) / page_size))
        for i in range(niterations):
            if prev_links:
                uri = self.get_bare_url(prev_links['previous'])
            else:
                pagination_args.update(self.list_kwargs)
                uri = self.list_client.build_uri(
                    self.plural_name, page_reverse=True, **pagination_args)
            prev_links, body = self.list_client.get_uri_with_links(
                self.plural_name, uri
            )
            resources_ = self._extract_resources(body)
            self.assertGreaterEqual(page_size, len(resources_))
            resources.extend(reversed(resources_))

        self.assertSameOrder(expected_resources, reversed(resources))

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse(
            direction=constants.SORT_DIRECTION_ASC)

    @_require_pagination
    @_require_sorting
    def _test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse(
            direction=constants.SORT_DIRECTION_DESC)

    def _test_list_pagination_page_reverse(self, direction):
        pagination_args = {
            'sort_dir': direction,
            'sort_key': self.field,
            'limit': 3,
        }
        body = self.list_method(**pagination_args)
        expected_resources = self._extract_resources(body)

        pagination_args['limit'] -= 1
        pagination_args['marker'] = expected_resources[-1]['id']
        pagination_args['page_reverse'] = True
        body = self.list_method(**pagination_args)

        self.assertSameOrder(
            # the last entry is not included in 2nd result when used as a
            # marker
            expected_resources[:-1],
            self._extract_resources(body))

    def _test_list_validation_filters(self):
        validation_args = {
            'unknown_filter': 'value',
        }
        body = self.list_method(**validation_args)
        resources = self._extract_resources(body)
        for resource in resources:
            self.assertIn(resource['name'], self.resource_names)
