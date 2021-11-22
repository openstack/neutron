# Copyright (c) 2015 Thales Services SAS
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
import functools

import fixtures
import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutronclient.common import exceptions

from neutron.common import utils


def _safe_method(f):
    @functools.wraps(f)
    def delete(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except exceptions.NotFound:
            pass
    return delete


class ClientFixture(fixtures.Fixture):
    """Manage and cleanup neutron resources."""

    def __init__(self, client):
        super(ClientFixture, self).__init__()
        self.client = client

    def _create_resource(self, resource_type, spec):
        create = getattr(self.client, 'create_%s' % resource_type)
        delete = getattr(self.client, 'delete_%s' % resource_type)

        body = {resource_type: spec}
        resp = create(body=body)
        data = resp[resource_type]
        self.addCleanup(_safe_method(delete), data['id'])
        return data

    def _update_resource(self, resource_type, id, spec):
        update = getattr(self.client, 'update_%s' % resource_type)

        body = {resource_type: spec}
        resp = update(id, body=body)
        return resp[resource_type]

    def _delete_resource(self, resource_type, id):
        delete = getattr(self.client, 'delete_%s' % resource_type)

        return delete(id)

    def create_local_ip(self, project_id, network_id=None):
        delete = self.delete_local_ip

        path = '/local_ips'
        body = {'local_ip': {'project_id': project_id,
                             'network_id': network_id}}
        resp = self.client.post(path, body=body)
        data = resp['local_ip']
        self.addCleanup(_safe_method(delete), data['id'])
        return data

    def create_local_ip_association(self, local_ip_id, port_id, fixed_ip=None):
        delete = self.delete_local_ip_association

        path = '/local_ips/{0}/port_associations'.format(local_ip_id)
        body = {'port_association': {'fixed_port_id': port_id}}
        if fixed_ip:
            body['port_association']['fixed_ip'] = fixed_ip
        resp = self.client.post(path, body=body)
        data = resp['port_association']
        self.addCleanup(_safe_method(delete), local_ip_id, port_id)
        return data

    def delete_local_ip(self, local_ip_id):
        path = "/local-ips/{0}".format(local_ip_id)
        self.client.delete(path)

    def delete_local_ip_association(self, local_ip_id, port_id):
        path = "/local_ips/{0}/port_associations/{1}".format(
            local_ip_id, port_id)
        self.client.delete(path)

    def create_router(self, tenant_id, name=None, ha=False,
                      external_network=None, external_subnet=None):
        resource_type = 'router'

        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name, 'ha': ha}
        if external_network:
            spec['external_gateway_info'] = {"network_id": external_network}
            if external_subnet:
                spec['external_gateway_info']['external_fixed_ips'] = (
                    [{"subnet_id": external_subnet}])

        return self._create_resource(resource_type, spec)

    def update_router(self, router_id, **kwargs):
        return self._update_resource('router', router_id, kwargs)

    def create_segment(self, project_id, network, name, network_type=None,
                       segmentation_id=None, physical_network=None):
        resource_type = 'segment'
        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'project_id': project_id, 'name': name, 'network_id': network,
                'network_type': network_type,
                'physical_network': physical_network,
                'segmentation_id': segmentation_id}
        return self._create_resource(resource_type, spec)

    def create_network(self, tenant_id, name=None, external=False,
                       network_type=None, segmentation_id=None,
                       physical_network=None, mtu=None, qos_policy_id=None):
        resource_type = 'network'

        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name}
        spec['router:external'] = external

        if segmentation_id is not None:
            spec['provider:segmentation_id'] = segmentation_id
        if network_type is not None:
            spec['provider:network_type'] = network_type
        if physical_network is not None:
            spec['provider:physical_network'] = physical_network
        if mtu is not None:
            spec['mtu'] = mtu
        if qos_policy_id is not None:
            spec['qos_policy_id'] = qos_policy_id

        return self._create_resource(resource_type, spec)

    def update_network(self, id, **kwargs):
        return self._update_resource('network', id, kwargs)

    def delete_network(self, id):
        return self._delete_resource('network', id)

    def create_subnet(self, tenant_id, network_id,
                      cidr=None, gateway_ip=None, name=None, enable_dhcp=True,
                      ipv6_address_mode='slaac', ipv6_ra_mode='slaac',
                      subnetpool_id=None, ip_version=None,
                      host_routes=None):
        resource_type = 'subnet'

        name = name or utils.get_rand_name(prefix=resource_type)
        if cidr and not ip_version:
            ip_version = netaddr.IPNetwork(cidr).version
        spec = {'tenant_id': tenant_id, 'network_id': network_id, 'name': name,
                'enable_dhcp': enable_dhcp, 'ip_version': ip_version}
        if ip_version == constants.IP_VERSION_6:
            spec['ipv6_address_mode'] = ipv6_address_mode
            spec['ipv6_ra_mode'] = ipv6_ra_mode

        if gateway_ip:
            spec['gateway_ip'] = gateway_ip
        if subnetpool_id:
            spec['subnetpool_id'] = subnetpool_id
        if cidr:
            spec['cidr'] = cidr
        if host_routes:
            spec['host_routes'] = host_routes

        return self._create_resource(resource_type, spec)

    def create_subnetpool(self, project_id, name=None, min_prefixlen=8,
                          max_prefixlen=24, default_prefixlen=24,
                          prefixes=None):
        resource_type = 'subnetpool'
        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'project_id': project_id,
                'name': name,
                'min_prefixlen': min_prefixlen,
                'max_prefixlen': max_prefixlen,
                'default_prefixlen': default_prefixlen,
                'is_default': False,
                'shared': False,
                'prefixes': prefixes}

        return self._create_resource(resource_type, spec)

    def list_subnets(self, retrieve_all=True, **kwargs):
        resp = self.client.list_subnets(retrieve_all=retrieve_all, **kwargs)
        return resp['subnets']

    def list_ports(self, retrieve_all=True, **kwargs):
        resp = self.client.list_ports(retrieve_all=retrieve_all, **kwargs)
        return resp['ports']

    def create_port(self, tenant_id, network_id, hostname=None,
                    qos_policy_id=None, security_groups=None, **kwargs):
        spec = {
            'network_id': network_id,
            'tenant_id': tenant_id,
        }
        spec.update(kwargs)
        if hostname is not None:
            spec[portbindings.HOST_ID] = hostname
        if qos_policy_id:
            spec['qos_policy_id'] = qos_policy_id
        if security_groups:
            spec['security_groups'] = security_groups
        return self._create_resource('port', spec)

    def update_port(self, port_id, **kwargs):
        return self._update_resource('port', port_id, kwargs)

    def create_floatingip(self, tenant_id, floating_network_id,
                          fixed_ip_address, port_id, qos_policy_id=None):
        spec = {
            'floating_network_id': floating_network_id,
            'tenant_id': tenant_id,
            'fixed_ip_address': fixed_ip_address,
            'port_id': port_id
        }

        if qos_policy_id:
            spec['qos_policy_id'] = qos_policy_id
        return self._create_resource('floatingip', spec)

    def add_router_interface(self, router_id, subnet_id):
        body = {'subnet_id': subnet_id}
        router_interface_info = self.client.add_interface_router(
            router=router_id, body=body)
        self.addCleanup(_safe_method(self.client.remove_interface_router),
                        router=router_id, body=body)
        return router_interface_info

    def create_qos_policy(self, tenant_id, name, description, shared,
                          is_default):
        policy = self.client.create_qos_policy(
            body={'policy': {'name': name,
                             'description': description,
                             'shared': shared,
                             'tenant_id': tenant_id,
                             'is_default': is_default}})

        def detach_and_delete_policy():
            qos_policy_id = policy['policy']['id']
            ports_with_policy = self.client.list_ports()['ports']
            for port in ports_with_policy:
                if qos_policy_id == port['qos_policy_id']:
                    self.client.update_port(
                        port['id'],
                        body={'port': {'qos_policy_id': None}})
            self.client.delete_qos_policy(qos_policy_id)

        # NOTE: We'll need to add support for detaching from network once
        # create_network() supports qos_policy_id.
        self.addCleanup(_safe_method(detach_and_delete_policy))

        return policy['policy']

    def create_bandwidth_limit_rule(self, tenant_id, qos_policy_id, limit=None,
                                    burst=None, direction=None):
        rule = {'tenant_id': tenant_id}
        if limit:
            rule['max_kbps'] = limit
        if burst:
            rule['max_burst_kbps'] = burst
        if direction:
            rule['direction'] = direction
        rule = self.client.create_bandwidth_limit_rule(
            policy=qos_policy_id,
            body={'bandwidth_limit_rule': rule})

        self.addCleanup(_safe_method(self.client.delete_bandwidth_limit_rule),
                        rule['bandwidth_limit_rule']['id'],
                        qos_policy_id)

        return rule['bandwidth_limit_rule']

    def create_packet_rate_limit_rule(
            self, project_id, qos_policy_id, limit=None,
            burst=None, direction=None):
        rule = {'project_id': project_id}
        if limit:
            rule['max_kpps'] = limit
        if burst:
            rule['max_burst_kpps'] = burst
        if direction:
            rule['direction'] = direction
        rule = self.client.create_packet_rate_limit_rule(
            policy=qos_policy_id,
            body={'packet_rate_limit_rule': rule})

        self.addCleanup(
            _safe_method(self.client.delete_packet_rate_limit_rule),
            rule['packet_rate_limit_rule']['id'],
            qos_policy_id)

        return rule['packet_rate_limit_rule']

    def create_minimum_bandwidth_rule(self, tenant_id, qos_policy_id,
                                      min_bw, direction=None):
        rule = {'tenant_id': tenant_id,
                'min_kbps': min_bw}
        if direction:
            rule['direction'] = direction
        rule = self.client.create_minimum_bandwidth_rule(
            policy=qos_policy_id,
            body={'minimum_bandwidth_rule': rule})

        self.addCleanup(_safe_method(
            self.client.delete_minimum_bandwidth_rule),
            rule['minimum_bandwidth_rule']['id'], qos_policy_id)

        return rule['minimum_bandwidth_rule']

    def create_dscp_marking_rule(self, tenant_id, qos_policy_id, dscp_mark=0):
        rule = {'tenant_id': tenant_id}
        if dscp_mark:
            rule['dscp_mark'] = dscp_mark
        rule = self.client.create_dscp_marking_rule(
            policy=qos_policy_id,
            body={'dscp_marking_rule': rule})

        self.addCleanup(_safe_method(self.client.delete_dscp_marking_rule),
                        rule['dscp_marking_rule']['id'],
                        qos_policy_id)

        return rule['dscp_marking_rule']

    def create_trunk(self, tenant_id, port_id, name=None,
                     admin_state_up=None, sub_ports=None):
        """Create a trunk via API.

        :param tenant_id: ID of the tenant.
        :param port_id: Parent port of trunk.
        :param name: Name of the trunk.
        :param admin_state_up: Admin state of the trunk.
        :param sub_ports: List of subport dictionaries in format
                {'port_id': <ID of neutron port for subport>,
                 'segmentation_type': 'vlan',
                 'segmentation_id': <VLAN tag>}

        :return: Dictionary with trunk's data returned from Neutron API.
        """
        spec = {
            'port_id': port_id,
            'tenant_id': tenant_id,
        }
        if name is not None:
            spec['name'] = name
        if sub_ports is not None:
            spec['sub_ports'] = sub_ports
        if admin_state_up is not None:
            spec['admin_state_up'] = admin_state_up

        trunk = self.client.create_trunk({'trunk': spec})['trunk']

        if sub_ports:
            self.addCleanup(
                _safe_method(self.trunk_remove_subports),
                tenant_id, trunk['id'], trunk['sub_ports'])
        self.addCleanup(_safe_method(self.client.delete_trunk), trunk['id'])

        return trunk

    def trunk_add_subports(self, tenant_id, trunk_id, sub_ports):
        """Add subports to the trunk.

        :param tenant_id: ID of the tenant.
        :param trunk_id: ID of the trunk.
        :param sub_ports: List of subport dictionaries to be added in format
                {'port_id': <ID of neutron port for subport>,
                 'segmentation_type': 'vlan',
                 'segmentation_id': <VLAN tag>}
        """
        spec = {
            'tenant_id': tenant_id,
            'sub_ports': sub_ports,
        }
        trunk = self.client.trunk_add_subports(trunk_id, spec)

        sub_ports_to_remove = [
            sub_port for sub_port in trunk['sub_ports']
            if sub_port in sub_ports]
        self.addCleanup(
            _safe_method(self.trunk_remove_subports), tenant_id, trunk_id,
            sub_ports_to_remove)

    def trunk_remove_subports(self, tenant_id, trunk_id, sub_ports):
        """Remove subports from the trunk.

        :param trunk_id: ID of the trunk.
        :param sub_ports: List of subport port IDs.
        """
        spec = {
            'tenant_id': tenant_id,
            'sub_ports': sub_ports,
        }
        return self.client.trunk_remove_subports(trunk_id, spec)

    def create_security_group(self, tenant_id, name=None, stateful=True):
        resource_type = 'security_group'

        name = name or utils.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name, 'stateful': stateful}

        return self._create_resource(resource_type, spec)

    def update_security_group(self, security_group_id, **kwargs):
        return self._update_resource('security_group', security_group_id,
                                     kwargs)

    def create_security_group_rule(self, tenant_id, security_group_id,
                                   **kwargs):
        resource_type = 'security_group_rule'

        spec = {'tenant_id': tenant_id,
                'security_group_id': security_group_id}
        spec.update(kwargs)

        return self._create_resource(resource_type, spec)

    def create_network_log(self, tenant_id, resource_type,
                           enabled=True, **kwargs):

        spec = {'project_id': tenant_id,
                'resource_type': resource_type,
                'enabled': enabled}
        spec.update(kwargs)

        net_log = self.client.create_network_log({'log': spec})
        self.addCleanup(
            _safe_method(self.client.delete_network_log), net_log['log']['id'])
        return net_log

    def update_quota(self, project_id, tracked_resource, quota):
        self._update_resource('quota', project_id, {tracked_resource: quota})
