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

import time

from oslo_serialization import jsonutils as json
from six.moves.urllib import parse as urlparse
from tempest.common import service_client
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest import exceptions


class NetworkClientJSON(service_client.ServiceClient):

    """
    Tempest REST client for Neutron. Uses v2 of the Neutron API, since the
    V1 API has been removed from the code base.

    Implements create, delete, update, list and show for the basic Neutron
    abstractions (networks, sub-networks, routers, ports and floating IP):

    Implements add/remove interface to router using subnet ID / port ID

    It also implements list, show, update and reset for OpenStack Networking
    quotas
    """

    version = '2.0'
    uri_prefix = "v2.0"

    def get_uri(self, plural_name):
        # get service prefix from resource name

        # The following list represents resource names that do not require
        # changing underscore to a hyphen
        hyphen_exceptions = [
            "firewall_rules", "firewall_policies", "service_profiles"]
        # the following map is used to construct proper URI
        # for the given neutron resource
        service_resource_prefix_map = {
            'bgp-peers': '',
            'bgp-speakers': '',
            'networks': '',
            'subnets': '',
            'subnetpools': '',
            'ports': '',
            'metering_labels': 'metering',
            'metering_label_rules': 'metering',
            'firewall_rules': 'fw',
            'firewall_policies': 'fw',
            'firewalls': 'fw',
            'policies': 'qos',
            'bandwidth_limit_rules': 'qos',
            'rule_types': 'qos',
            'rbac-policies': '',
        }
        service_prefix = service_resource_prefix_map.get(
            plural_name)
        if plural_name not in hyphen_exceptions:
            plural_name = plural_name.replace("_", "-")
        if service_prefix:
            uri = '%s/%s/%s' % (self.uri_prefix, service_prefix,
                                plural_name)
        else:
            uri = '%s/%s' % (self.uri_prefix, plural_name)
        return uri

    def pluralize(self, resource_name):
        # get plural from map or just add 's'

        # map from resource name to a plural name
        # needed only for those which can't be constructed as name + 's'
        resource_plural_map = {
            'security_groups': 'security_groups',
            'security_group_rules': 'security_group_rules',
            'quotas': 'quotas',
            'firewall_policy': 'firewall_policies',
            'qos_policy': 'policies',
            'rbac_policy': 'rbac_policies',
        }
        return resource_plural_map.get(resource_name, resource_name + 's')

    def _lister(self, plural_name):
        def _list(**filters):
            uri = self.get_uri(plural_name)
            if filters:
                uri += '?' + urlparse.urlencode(filters, doseq=1)
            resp, body = self.get(uri)
            result = {plural_name: self.deserialize_list(body)}
            self.expected_success(200, resp.status)
            return service_client.ResponseBody(resp, result)

        return _list

    def _deleter(self, resource_name):
        def _delete(resource_id):
            plural = self.pluralize(resource_name)
            uri = '%s/%s' % (self.get_uri(plural), resource_id)
            resp, body = self.delete(uri)
            self.expected_success(204, resp.status)
            return service_client.ResponseBody(resp, body)

        return _delete

    def _shower(self, resource_name):
        def _show(resource_id, **fields):
            # fields is a dict which key is 'fields' and value is a
            # list of field's name. An example:
            # {'fields': ['id', 'name']}
            plural = self.pluralize(resource_name)
            uri = '%s/%s' % (self.get_uri(plural), resource_id)
            if fields:
                uri += '?' + urlparse.urlencode(fields, doseq=1)
            resp, body = self.get(uri)
            body = self.deserialize_single(body)
            self.expected_success(200, resp.status)
            return service_client.ResponseBody(resp, body)

        return _show

    def _creater(self, resource_name):
        def _create(**kwargs):
            plural = self.pluralize(resource_name)
            uri = self.get_uri(plural)
            post_data = self.serialize({resource_name: kwargs})
            resp, body = self.post(uri, post_data)
            body = self.deserialize_single(body)
            self.expected_success(201, resp.status)
            return service_client.ResponseBody(resp, body)

        return _create

    def _updater(self, resource_name):
        def _update(res_id, **kwargs):
            plural = self.pluralize(resource_name)
            uri = '%s/%s' % (self.get_uri(plural), res_id)
            post_data = self.serialize({resource_name: kwargs})
            resp, body = self.put(uri, post_data)
            body = self.deserialize_single(body)
            self.expected_success(200, resp.status)
            return service_client.ResponseBody(resp, body)

        return _update

    def __getattr__(self, name):
        method_prefixes = ["list_", "delete_", "show_", "create_", "update_"]
        method_functors = [self._lister,
                           self._deleter,
                           self._shower,
                           self._creater,
                           self._updater]
        for index, prefix in enumerate(method_prefixes):
            prefix_len = len(prefix)
            if name[:prefix_len] == prefix:
                return method_functors[index](name[prefix_len:])
        raise AttributeError(name)

    # Subnetpool methods
    def create_subnetpool(self, name, **kwargs):
        subnetpool_data = {'name': name}
        for arg in kwargs:
           subnetpool_data[arg] = kwargs[arg]

        post_data = {'subnetpool': subnetpool_data}
        body = self.serialize_list(post_data, "subnetpools", "subnetpool")
        uri = self.get_uri("subnetpools")
        resp, body = self.post(uri, body)
        body = {'subnetpool': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_subnetpool(self, id):
        uri = self.get_uri("subnetpools")
        subnetpool_uri = '%s/%s' % (uri, id)
        resp, body = self.get(subnetpool_uri)
        body = {'subnetpool': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_subnetpool(self, id):
        uri = self.get_uri("subnetpools")
        subnetpool_uri = '%s/%s' % (uri, id)
        resp, body = self.delete(subnetpool_uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_subnetpools(self, **filters):
        uri = self.get_uri("subnetpools")
        if filters:
            uri = '?'.join([uri, urlparse.urlencode(filters)])
        resp, body = self.get(uri)
        body = {'subnetpools': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_subnetpool(self, id, **kwargs):
        subnetpool_data = {}
        for arg in kwargs:
           subnetpool_data[arg] = kwargs[arg]

        post_data = {'subnetpool': subnetpool_data}
        body = self.serialize_list(post_data, "subnetpools", "subnetpool")
        uri = self.get_uri("subnetpools")
        subnetpool_uri = '%s/%s' % (uri, id)
        resp, body = self.put(subnetpool_uri, body)
        body = {'subnetpool': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    # BGP speaker methods
    def create_bgp_speaker(self, post_data):
        body = self.serialize_list(post_data, "bgp-speakers", "bgp-speaker")
        uri = self.get_uri("bgp-speakers")
        resp, body = self.post(uri, body)
        body = {'bgp-speaker': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_bgp_speaker(self, id):
        uri = self.get_uri("bgp-speakers")
        bgp_speaker_uri = '%s/%s' % (uri, id)
        resp, body = self.get(bgp_speaker_uri)
        body = {'bgp-speaker': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_bgp_speakers(self):
        uri = self.get_uri("bgp-speakers")
        resp, body = self.get(uri)
        body = {'bgp-speakers': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_bgp_speaker(self, id, put_data):
        body = self.serialize_list(put_data, "bgp-speakers", "bgp-speaker")
        uri = self.get_uri("bgp-speakers")
        bgp_speaker_uri = '%s/%s' % (uri, id)
        resp, body = self.put(bgp_speaker_uri, body)
        body = {'bgp-speaker': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_bgp_speaker(self, id):
        uri = self.get_uri("bgp-speakers")
        bgp_speaker_uri = '%s/%s' % (uri, id)
        resp, body = self.delete(bgp_speaker_uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bgp_peer(self, post_data):
        body = self.serialize_list(post_data, "bgp-peers", "bgp-peer")
        uri = self.get_uri("bgp-peers")
        resp, body = self.post(uri, body)
        body = {'bgp-peer': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def get_bgp_peer(self, id):
        uri = self.get_uri("bgp-peers")
        bgp_speaker_uri = '%s/%s' % (uri, id)
        resp, body = self.get(bgp_speaker_uri)
        body = {'bgp-peer': self.deserialize_list(body)}
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_bgp_peer(self, id):
        uri = self.get_uri("bgp-peers")
        bgp_speaker_uri = '%s/%s' % (uri, id)
        resp, body = self.delete(bgp_speaker_uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def add_bgp_peer_with_id(self, bgp_speaker_id, bgp_peer_id):
        uri = '%s/bgp-speakers/%s/add_bgp_peer' % (self.uri_prefix,
                                                   bgp_speaker_id)
        update_body = {"bgp_peer_id": bgp_peer_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_bgp_peer_with_id(self, bgp_speaker_id, bgp_peer_id):
        uri = '%s/bgp-speakers/%s/remove_bgp_peer' % (self.uri_prefix,
                                                      bgp_speaker_id)
        update_body = {"bgp_peer_id": bgp_peer_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_bgp_gateway_network(self, bgp_speaker_id, network_id):
        uri = '%s/bgp-speakers/%s/add_gateway_network' % (self.uri_prefix,
                                                        bgp_speaker_id)
        update_body = {"network_id": network_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_bgp_gateway_network(self, bgp_speaker_id, network_id):
        uri = '%s/bgp-speakers/%s/remove_gateway_network'
        uri = uri % (self.uri_prefix, bgp_speaker_id)
        update_body = {"network_id": network_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    # Common methods that are hard to automate
    def create_bulk_network(self, names, shared=False):
        network_list = [{'name': name, 'shared': shared} for name in names]
        post_data = {'networks': network_list}
        body = self.serialize_list(post_data, "networks", "network")
        uri = self.get_uri("networks")
        resp, body = self.post(uri, body)
        body = {'networks': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bulk_subnet(self, subnet_list):
        post_data = {'subnets': subnet_list}
        body = self.serialize_list(post_data, 'subnets', 'subnet')
        uri = self.get_uri('subnets')
        resp, body = self.post(uri, body)
        body = {'subnets': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bulk_port(self, port_list):
        post_data = {'ports': port_list}
        body = self.serialize_list(post_data, 'ports', 'port')
        uri = self.get_uri('ports')
        resp, body = self.post(uri, body)
        body = {'ports': self.deserialize_list(body)}
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def wait_for_resource_deletion(self, resource_type, id):
        """Waits for a resource to be deleted."""
        start_time = int(time.time())
        while True:
            if self.is_resource_deleted(resource_type, id):
                return
            if int(time.time()) - start_time >= self.build_timeout:
                raise exceptions.TimeoutException
            time.sleep(self.build_interval)

    def is_resource_deleted(self, resource_type, id):
        method = 'show_' + resource_type
        try:
            getattr(self, method)(id)
        except AttributeError:
            raise Exception("Unknown resource type %s " % resource_type)
        except lib_exc.NotFound:
            return True
        return False

    def deserialize_single(self, body):
        return json.loads(body)

    def deserialize_list(self, body):
        res = json.loads(body)
        # expecting response in form
        # {'resources': [ res1, res2] } => when pagination disabled
        # {'resources': [..], 'resources_links': {}} => if pagination enabled
        for k in res.keys():
            if k.endswith("_links"):
                continue
            return res[k]

    def serialize(self, data):
        return json.dumps(data)

    def serialize_list(self, data, root=None, item=None):
        return self.serialize(data)

    def update_quotas(self, tenant_id, **kwargs):
        put_body = {'quota': kwargs}
        body = json.dumps(put_body)
        uri = '%s/quotas/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body['quota'])

    def reset_quotas(self, tenant_id):
        uri = '%s/quotas/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_router(self, name, admin_state_up=True, **kwargs):
        post_body = {'router': kwargs}
        post_body['router']['name'] = name
        post_body['router']['admin_state_up'] = admin_state_up
        body = json.dumps(post_body)
        uri = '%s/routers' % (self.uri_prefix)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def _update_router(self, router_id, set_enable_snat, **kwargs):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        update_body = {}
        update_body['name'] = kwargs.get('name', body['router']['name'])
        update_body['admin_state_up'] = kwargs.get(
            'admin_state_up', body['router']['admin_state_up'])
        cur_gw_info = body['router']['external_gateway_info']
        if cur_gw_info:
            # TODO(kevinbenton): setting the external gateway info is not
            # allowed for a regular tenant. If the ability to update is also
            # merged, a test case for this will need to be added similar to
            # the SNAT case.
            cur_gw_info.pop('external_fixed_ips', None)
            if not set_enable_snat:
                cur_gw_info.pop('enable_snat', None)
        update_body['external_gateway_info'] = kwargs.get(
            'external_gateway_info', body['router']['external_gateway_info'])
        if 'distributed' in kwargs:
            update_body['distributed'] = kwargs['distributed']
        update_body = dict(router=update_body)
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_router(self, router_id, **kwargs):
        """Update a router leaving enable_snat to its default value."""
        # If external_gateway_info contains enable_snat the request will fail
        # with 404 unless executed with admin client, and therefore we instruct
        # _update_router to not set this attribute
        # NOTE(salv-orlando): The above applies as long as Neutron's default
        # policy is to restrict enable_snat usage to admins only.
        return self._update_router(router_id, set_enable_snat=False, **kwargs)

    def update_router_with_snat_gw_info(self, router_id, **kwargs):
        """Update a router passing also the enable_snat attribute.

        This method must be execute with admin credentials, otherwise the API
        call will return a 404 error.
        """
        return self._update_router(router_id, set_enable_snat=True, **kwargs)

    def add_router_interface_with_subnet_id(self, router_id, subnet_id):
        uri = '%s/routers/%s/add_router_interface' % (self.uri_prefix,
                                                      router_id)
        update_body = {"subnet_id": subnet_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_router_interface_with_port_id(self, router_id, port_id):
        uri = '%s/routers/%s/add_router_interface' % (self.uri_prefix,
                                                      router_id)
        update_body = {"port_id": port_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_interface_with_subnet_id(self, router_id, subnet_id):
        uri = '%s/routers/%s/remove_router_interface' % (self.uri_prefix,
                                                         router_id)
        update_body = {"subnet_id": subnet_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_interface_with_port_id(self, router_id, port_id):
        uri = '%s/routers/%s/remove_router_interface' % (self.uri_prefix,
                                                         router_id)
        update_body = {"port_id": port_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_router_interfaces(self, uuid):
        uri = '%s/ports?device_id=%s' % (self.uri_prefix, uuid)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_agent(self, agent_id, agent_info):
        """
        :param agent_info: Agent update information.
        E.g {"admin_state_up": True}
        """
        uri = '%s/agents/%s' % (self.uri_prefix, agent_id)
        agent = {"agent": agent_info}
        body = json.dumps(agent)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_routers_on_l3_agent(self, agent_id):
        uri = '%s/agents/%s/l3-routers' % (self.uri_prefix, agent_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_l3_agents_hosting_router(self, router_id):
        uri = '%s/routers/%s/l3-agents' % (self.uri_prefix, router_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_router_to_l3_agent(self, agent_id, router_id):
        uri = '%s/agents/%s/l3-routers' % (self.uri_prefix, agent_id)
        post_body = {"router_id": router_id}
        body = json.dumps(post_body)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_router_from_l3_agent(self, agent_id, router_id):
        uri = '%s/agents/%s/l3-routers/%s' % (
            self.uri_prefix, agent_id, router_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_dhcp_agent_hosting_network(self, network_id):
        uri = '%s/networks/%s/dhcp-agents' % (self.uri_prefix, network_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_networks_hosted_by_one_dhcp_agent(self, agent_id):
        uri = '%s/agents/%s/dhcp-networks' % (self.uri_prefix, agent_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_network_from_dhcp_agent(self, agent_id, network_id):
        uri = '%s/agents/%s/dhcp-networks/%s' % (self.uri_prefix, agent_id,
                                                 network_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_extra_routes(self, router_id, nexthop, destination):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        put_body = {
            'router': {
                'routes': [{'nexthop': nexthop,
                            "destination": destination}]
            }
        }
        body = json.dumps(put_body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_extra_routes(self, router_id):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        null_routes = None
        put_body = {
            'router': {
                'routes': null_routes
            }
        }
        body = json.dumps(put_body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def add_dhcp_agent_to_network(self, agent_id, network_id):
        post_body = {'network_id': network_id}
        body = json.dumps(post_body)
        uri = '%s/agents/%s/dhcp-networks' % (self.uri_prefix, agent_id)
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def insert_firewall_rule_in_policy(self, firewall_policy_id,
                                       firewall_rule_id, insert_after="",
                                       insert_before=""):
        uri = '%s/fw/firewall_policies/%s/insert_rule' % (self.uri_prefix,
                                                          firewall_policy_id)
        body = {
            "firewall_rule_id": firewall_rule_id,
            "insert_after": insert_after,
            "insert_before": insert_before
        }
        body = json.dumps(body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def remove_firewall_rule_from_policy(self, firewall_policy_id,
                                         firewall_rule_id):
        uri = '%s/fw/firewall_policies/%s/remove_rule' % (self.uri_prefix,
                                                          firewall_policy_id)
        update_body = {"firewall_rule_id": firewall_rule_id}
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_qos_policies(self, **filters):
        if filters:
            uri = '%s/qos/policies?%s' % (self.uri_prefix,
                                          urlparse.urlencode(filters))
        else:
            uri = '%s/qos/policies' % self.uri_prefix
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_qos_policy(self, name, description, shared, tenant_id=None):
        uri = '%s/qos/policies' % self.uri_prefix
        post_data = {'policy': {
                'name': name,
                'description': description,
                'shared': shared
            }}
        if tenant_id is not None:
            post_data['policy']['tenant_id'] = tenant_id
        resp, body = self.post(uri, self.serialize(post_data))
        body = self.deserialize_single(body)
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_qos_policy(self, policy_id, **kwargs):
        uri = '%s/qos/policies/%s' % (self.uri_prefix, policy_id)
        post_data = self.serialize({'policy': kwargs})
        resp, body = self.put(uri, post_data)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def create_bandwidth_limit_rule(self, policy_id, max_kbps, max_burst_kbps):
        uri = '%s/qos/policies/%s/bandwidth_limit_rules' % (
            self.uri_prefix, policy_id)
        post_data = self.serialize(
            {'bandwidth_limit_rule': {
                'max_kbps': max_kbps,
                'max_burst_kbps': max_burst_kbps}
            })
        resp, body = self.post(uri, post_data)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_bandwidth_limit_rules(self, policy_id):
        uri = '%s/qos/policies/%s/bandwidth_limit_rules' % (
            self.uri_prefix, policy_id)
        resp, body = self.get(uri)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def show_bandwidth_limit_rule(self, policy_id, rule_id):
        uri = '%s/qos/policies/%s/bandwidth_limit_rules/%s' % (
            self.uri_prefix, policy_id, rule_id)
        resp, body = self.get(uri)
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_bandwidth_limit_rule(self, policy_id, rule_id, **kwargs):
        uri = '%s/qos/policies/%s/bandwidth_limit_rules/%s' % (
            self.uri_prefix, policy_id, rule_id)
        post_data = {'bandwidth_limit_rule': kwargs}
        resp, body = self.put(uri, json.dumps(post_data))
        body = self.deserialize_single(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_bandwidth_limit_rule(self, policy_id, rule_id):
        uri = '%s/qos/policies/%s/bandwidth_limit_rules/%s' % (
            self.uri_prefix, policy_id, rule_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_qos_rule_types(self):
        uri = '%s/qos/rule-types' % self.uri_prefix
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_auto_allocated_topology(self, tenant_id=None):
        uri = '%s/auto-allocated-topology/%s' % (self.uri_prefix, tenant_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)
