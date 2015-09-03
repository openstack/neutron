# Copyright 2013 IBM Corp.
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
from neutron.tests.tempest.common import cred_provider
from neutron.tests.tempest import config
from neutron.tests.tempest import exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


class IsolatedCreds(cred_provider.CredentialProvider):

    def __init__(self, name, password='pass', network_resources=None):
        super(IsolatedCreds, self).__init__(name, password, network_resources)
        self.network_resources = network_resources
        self.isolated_creds = {}
        self.isolated_net_resources = {}
        self.ports = []
        self.password = password
        self.identity_admin_client, self.network_admin_client = (
            self._get_admin_clients())

    def _get_admin_clients(self):
        """
        Returns a tuple with instances of the following admin clients (in this
        order):
            identity
            network
        """
        os = clients.AdminManager()
        return os.identity_client, os.network_client

    def _create_tenant(self, name, description):
        tenant = self.identity_admin_client.create_tenant(
            name=name, description=description)
        return tenant

    def _get_tenant_by_name(self, name):
        tenant = self.identity_admin_client.get_tenant_by_name(name)
        return tenant

    def _create_user(self, username, password, tenant, email):
        user = self.identity_admin_client.create_user(
            username, password, tenant['id'], email)
        return user

    def _get_user(self, tenant, username):
        user = self.identity_admin_client.get_user_by_username(
            tenant['id'], username)
        return user

    def _list_roles(self):
        roles = self.identity_admin_client.list_roles()
        return roles

    def _assign_user_role(self, tenant, user, role_name):
        role = None
        try:
            roles = self._list_roles()
            role = next(r for r in roles if r['name'] == role_name)
        except StopIteration:
            msg = 'No "%s" role found' % role_name
            raise lib_exc.NotFound(msg)
        try:
            self.identity_admin_client.assign_user_role(tenant['id'],
                                                        user['id'],
                                                        role['id'])
        except lib_exc.Conflict:
            LOG.warning('Trying to add %s for user %s in tenant %s but they '
                        ' were already granted that role' % (role_name,
                                                             user['name'],
                                                             tenant['name']))

    def _delete_user(self, user):
        self.identity_admin_client.delete_user(user)

    def _delete_tenant(self, tenant):
        if CONF.service_available.neutron:
            self._cleanup_default_secgroup(tenant)
        self.identity_admin_client.delete_tenant(tenant)

    def _create_creds(self, suffix="", admin=False, roles=None):
        """Create random credentials under the following schema.

        If the name contains a '.' is the full class path of something, and
        we don't really care. If it isn't, it's probably a meaningful name,
        so use it.

        For logging purposes, -user and -tenant are long and redundant,
        don't use them. The user# will be sufficient to figure it out.
        """
        if '.' in self.name:
            root = ""
        else:
            root = self.name

        tenant_name = data_utils.rand_name(root) + suffix
        tenant_desc = tenant_name + "-desc"
        tenant = self._create_tenant(name=tenant_name,
                                     description=tenant_desc)

        username = data_utils.rand_name(root) + suffix
        email = data_utils.rand_name(root) + suffix + "@example.com"
        user = self._create_user(username, self.password,
                                 tenant, email)
        if admin:
            self._assign_user_role(tenant, user, CONF.identity.admin_role)
        # Add roles specified in config file
        for conf_role in CONF.auth.tempest_roles:
            self._assign_user_role(tenant, user, conf_role)
        # Add roles requested by caller
        if roles:
            for role in roles:
                self._assign_user_role(tenant, user, role)
        return self._get_credentials(user, tenant)

    def _get_credentials(self, user, tenant):
        return cred_provider.get_credentials(
            username=user['name'], user_id=user['id'],
            tenant_name=tenant['name'], tenant_id=tenant['id'],
            password=self.password)

    def _create_network_resources(self, tenant_id):
        network = None
        subnet = None
        router = None
        # Make sure settings
        if self.network_resources:
            if self.network_resources['router']:
                if (not self.network_resources['subnet'] or
                    not self.network_resources['network']):
                    raise exceptions.InvalidConfiguration(
                        'A router requires a subnet and network')
            elif self.network_resources['subnet']:
                if not self.network_resources['network']:
                    raise exceptions.InvalidConfiguration(
                        'A subnet requires a network')
            elif self.network_resources['dhcp']:
                raise exceptions.InvalidConfiguration('DHCP requires a subnet')

        data_utils.rand_name_root = data_utils.rand_name(self.name)
        if not self.network_resources or self.network_resources['network']:
            network_name = data_utils.rand_name_root + "-network"
            network = self._create_network(network_name, tenant_id)
        try:
            if not self.network_resources or self.network_resources['subnet']:
                subnet_name = data_utils.rand_name_root + "-subnet"
                subnet = self._create_subnet(subnet_name, tenant_id,
                                             network['id'])
            if not self.network_resources or self.network_resources['router']:
                router_name = data_utils.rand_name_root + "-router"
                router = self._create_router(router_name, tenant_id)
                self._add_router_interface(router['id'], subnet['id'])
        except Exception:
            if router:
                self._clear_isolated_router(router['id'], router['name'])
            if subnet:
                self._clear_isolated_subnet(subnet['id'], subnet['name'])
            if network:
                self._clear_isolated_network(network['id'], network['name'])
            raise
        return network, subnet, router

    def _create_network(self, name, tenant_id):
        resp_body = self.network_admin_client.create_network(
            name=name, tenant_id=tenant_id)
        return resp_body['network']

    def _create_subnet(self, subnet_name, tenant_id, network_id):
        base_cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr)
        mask_bits = CONF.network.tenant_network_mask_bits
        for subnet_cidr in base_cidr.subnet(mask_bits):
            try:
                if self.network_resources:
                    resp_body = self.network_admin_client.\
                        create_subnet(
                            network_id=network_id, cidr=str(subnet_cidr),
                            name=subnet_name,
                            tenant_id=tenant_id,
                            enable_dhcp=self.network_resources['dhcp'],
                            ip_version=4)
                else:
                    resp_body = self.network_admin_client.\
                        create_subnet(network_id=network_id,
                                      cidr=str(subnet_cidr),
                                      name=subnet_name,
                                      tenant_id=tenant_id,
                                      ip_version=4)
                break
            except lib_exc.BadRequest as e:
                if 'overlaps with another subnet' not in str(e):
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise Exception(message)
        return resp_body['subnet']

    def _create_router(self, router_name, tenant_id):
        external_net_id = dict(
            network_id=CONF.network.public_network_id)
        resp_body = self.network_admin_client.create_router(
            router_name,
            external_gateway_info=external_net_id,
            tenant_id=tenant_id)
        return resp_body['router']

    def _add_router_interface(self, router_id, subnet_id):
        self.network_admin_client.add_router_interface_with_subnet_id(
            router_id, subnet_id)

    def get_primary_network(self):
        return self.isolated_net_resources.get('primary')[0]

    def get_primary_subnet(self):
        return self.isolated_net_resources.get('primary')[1]

    def get_primary_router(self):
        return self.isolated_net_resources.get('primary')[2]

    def get_admin_network(self):
        return self.isolated_net_resources.get('admin')[0]

    def get_admin_subnet(self):
        return self.isolated_net_resources.get('admin')[1]

    def get_admin_router(self):
        return self.isolated_net_resources.get('admin')[2]

    def get_alt_network(self):
        return self.isolated_net_resources.get('alt')[0]

    def get_alt_subnet(self):
        return self.isolated_net_resources.get('alt')[1]

    def get_alt_router(self):
        return self.isolated_net_resources.get('alt')[2]

    def get_credentials(self, credential_type):
        if self.isolated_creds.get(str(credential_type)):
            credentials = self.isolated_creds[str(credential_type)]
        else:
            if credential_type in ['primary', 'alt', 'admin']:
                is_admin = (credential_type == 'admin')
                credentials = self._create_creds(admin=is_admin)
            else:
                credentials = self._create_creds(roles=credential_type)
            self.isolated_creds[str(credential_type)] = credentials
            # Maintained until tests are ported
            LOG.info("Acquired isolated creds:\n credentials: %s"
                     % credentials)
            if (CONF.service_available.neutron and
                not CONF.baremetal.driver_enabled):
                network, subnet, router = self._create_network_resources(
                    credentials.tenant_id)
                self.isolated_net_resources[str(credential_type)] = (
                    network, subnet, router,)
                LOG.info("Created isolated network resources for : \n"
                         + " credentials: %s" % credentials)
        return credentials

    def get_primary_creds(self):
        return self.get_credentials('primary')

    def get_admin_creds(self):
        return self.get_credentials('admin')

    def get_alt_creds(self):
        return self.get_credentials('alt')

    def get_creds_by_roles(self, roles, force_new=False):
        roles = list(set(roles))
        # The roles list as a str will become the index as the dict key for
        # the created credentials set in the isolated_creds dict.
        exist_creds = self.isolated_creds.get(str(roles))
        # If force_new flag is True 2 cred sets with the same roles are needed
        # handle this by creating a separate index for old one to store it
        # separately for cleanup
        if exist_creds and force_new:
            new_index = str(roles) + '-' + str(len(self.isolated_creds))
            self.isolated_creds[new_index] = exist_creds
            del self.isolated_creds[str(roles)]
            # Handle isolated neutron resouces if they exist too
            if CONF.service_available.neutron:
                exist_net = self.isolated_net_resources.get(str(roles))
                if exist_net:
                    self.isolated_net_resources[new_index] = exist_net
                    del self.isolated_net_resources[str(roles)]
        return self.get_credentials(roles)

    def _clear_isolated_router(self, router_id, router_name):
        net_client = self.network_admin_client
        try:
            net_client.delete_router(router_id)
        except lib_exc.NotFound:
            LOG.warn('router with name: %s not found for delete' %
                     router_name)

    def _clear_isolated_subnet(self, subnet_id, subnet_name):
        net_client = self.network_admin_client
        try:
            net_client.delete_subnet(subnet_id)
        except lib_exc.NotFound:
            LOG.warn('subnet with name: %s not found for delete' %
                     subnet_name)

    def _clear_isolated_network(self, network_id, network_name):
        net_client = self.network_admin_client
        try:
            net_client.delete_network(network_id)
        except lib_exc.NotFound:
            LOG.warn('network with name: %s not found for delete' %
                     network_name)

    def _cleanup_default_secgroup(self, tenant):
        net_client = self.network_admin_client
        resp_body = net_client.list_security_groups(tenant_id=tenant,
                                                    name="default")
        secgroups_to_delete = resp_body['security_groups']
        for secgroup in secgroups_to_delete:
            try:
                net_client.delete_security_group(secgroup['id'])
            except lib_exc.NotFound:
                LOG.warn('Security group %s, id %s not found for clean-up' %
                         (secgroup['name'], secgroup['id']))

    def _clear_isolated_net_resources(self):
        net_client = self.network_admin_client
        for cred in self.isolated_net_resources:
            network, subnet, router = self.isolated_net_resources.get(cred)
            LOG.debug("Clearing network: %(network)s, "
                      "subnet: %(subnet)s, router: %(router)s",
                      {'network': network, 'subnet': subnet, 'router': router})
            if (not self.network_resources or
                self.network_resources.get('router')):
                try:
                    net_client.remove_router_interface_with_subnet_id(
                        router['id'], subnet['id'])
                except lib_exc.NotFound:
                    LOG.warn('router with name: %s not found for delete' %
                             router['name'])
                self._clear_isolated_router(router['id'], router['name'])
            if (not self.network_resources or
                self.network_resources.get('subnet')):
                self._clear_isolated_subnet(subnet['id'], subnet['name'])
            if (not self.network_resources or
                self.network_resources.get('network')):
                self._clear_isolated_network(network['id'], network['name'])
        self.isolated_net_resources = {}

    def clear_isolated_creds(self):
        if not self.isolated_creds:
            return
        self._clear_isolated_net_resources()
        for creds in self.isolated_creds.values():
            try:
                self._delete_user(creds.user_id)
            except lib_exc.NotFound:
                LOG.warn("user with name: %s not found for delete" %
                         creds.username)
            try:
                self._delete_tenant(creds.tenant_id)
            except lib_exc.NotFound:
                LOG.warn("tenant with name: %s not found for delete" %
                         creds.tenant_name)
        self.isolated_creds = {}

    def is_multi_user(self):
        return True

    def is_multi_tenant(self):
        return True

    def is_role_available(self, role):
        return True
