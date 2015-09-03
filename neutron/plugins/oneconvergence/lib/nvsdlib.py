# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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

"""Intermidiate NVSD Library."""

from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils

import neutron.plugins.oneconvergence.lib.exception as nvsdexception
from neutron.plugins.oneconvergence.lib import plugin_helper

LOG = logging.getLogger(__name__)

NETWORKS_URI = "/pluginhandler/ocplugin/tenant/%s/lnetwork/"
NETWORK_URI = NETWORKS_URI + "%s"
GET_ALL_NETWORKS = "/pluginhandler/ocplugin/tenant/getallnetworks"

SUBNETS_URI = NETWORK_URI + "/lsubnet/"
SUBNET_URI = SUBNETS_URI + "%s"
GET_ALL_SUBNETS = "/pluginhandler/ocplugin/tenant/getallsubnets"

PORTS_URI = NETWORK_URI + "/lport/"
PORT_URI = PORTS_URI + "%s"

EXT_URI = "/pluginhandler/ocplugin/ext/tenant/%s"
FLOATING_IPS_URI = EXT_URI + "/floatingip/"
FLOATING_IP_URI = FLOATING_IPS_URI + "%s"

ROUTERS_URI = EXT_URI + "/lrouter/"
ROUTER_URI = ROUTERS_URI + "%s"

METHODS = {"POST": "create",
           "PUT": "update",
           "DELETE": "delete",
           "GET": "get"}


class NVSDApi(object):

    def build_error_msg(self, method, resource, tenant_id, resource_id):
        if method == "POST":
            msg = _("Could not create a %(resource)s under tenant "
                    "%(tenant_id)s") % {'resource': resource,
                                        'tenant_id': tenant_id}
        elif resource_id:
            msg = _("Failed to %(method)s %(resource)s "
                    "id=%(resource_id)s") % {'method': METHODS[method],
                                             'resource': resource,
                                             'resource_id': resource_id
                                             }
        else:
            msg = _("Failed to %(method)s %(resource)s") % {
                'method': METHODS[method], 'resource': resource}
        return msg

    def set_connection(self):
        self.nvsdcontroller = plugin_helper.initialize_plugin_helper()
        self.nvsdcontroller.login()

    def send_request(self, method, uri, body=None, resource=None,
                     tenant_id='', resource_id=None):
        """Issue a request to NVSD controller."""

        try:
            result = self.nvsdcontroller.request(method, uri, body=body)
        except nvsdexception.NVSDAPIException as e:
            with excutils.save_and_reraise_exception() as ctxt:
                msg = self.build_error_msg(method, resource, tenant_id,
                                           resource_id)
                LOG.error(msg)
                # Modifying the reason message without disturbing the exception
                # info
                ctxt.value = type(e)(reason=msg)
        return result

    def create_network(self, network):

        tenant_id = network['tenant_id']
        router_external = network['router:external'] is True

        network_obj = {
            "name": network['name'],
            "tenant_id": tenant_id,
            "shared": network['shared'],
            "admin_state_up": network['admin_state_up'],
            "router:external": router_external
        }

        uri = NETWORKS_URI % tenant_id

        response = self.send_request("POST", uri,
                                     body=jsonutils.dumps(network_obj),
                                     resource='network', tenant_id=tenant_id)

        nvsd_net = response.json()

        LOG.debug("Network %(id)s created under tenant %(tenant_id)s",
                  {'id': nvsd_net['id'], 'tenant_id': tenant_id})

        return nvsd_net

    def update_network(self, network, network_update):

        tenant_id = network['tenant_id']
        network_id = network['id']

        uri = NETWORK_URI % (tenant_id, network_id)

        self.send_request("PUT", uri,
                          body=jsonutils.dumps(network_update),
                          resource='network', tenant_id=tenant_id,
                          resource_id=network_id)

        LOG.debug("Network %(id)s updated under tenant %(tenant_id)s",
                  {'id': network_id, 'tenant_id': tenant_id})

    def delete_network(self, network, subnets=[]):

        tenant_id = network['tenant_id']
        network_id = network['id']

        ports = self._get_ports(tenant_id, network_id)

        for port in ports:
            self.delete_port(port['id'], port)

        for subnet in subnets:
            self.delete_subnet(subnet)

        path = NETWORK_URI % (tenant_id, network_id)

        self.send_request("DELETE", path, resource='network',
                          tenant_id=tenant_id, resource_id=network_id)

        LOG.debug("Network %(id)s deleted under tenant %(tenant_id)s",
                  {'id': network_id, 'tenant_id': tenant_id})

    def create_subnet(self, subnet):

        tenant_id = subnet['tenant_id']
        network_id = subnet['network_id']

        uri = SUBNETS_URI % (tenant_id, network_id)

        self.send_request("POST", uri, body=jsonutils.dumps(subnet),
                          resource='subnet', tenant_id=tenant_id)

        LOG.debug("Subnet %(id)s created under tenant %(tenant_id)s",
                  {'id': subnet['id'], 'tenant_id': tenant_id})

    def delete_subnet(self, subnet):

        tenant_id = subnet['tenant_id']
        network_id = subnet['network_id']
        subnet_id = subnet['id']

        uri = SUBNET_URI % (tenant_id, network_id, subnet_id)

        self.send_request("DELETE", uri, resource='subnet',
                          tenant_id=tenant_id, resource_id=subnet_id)

        LOG.debug("Subnet %(id)s deleted under tenant %(tenant_id)s",
                  {'id': subnet_id, 'tenant_id': tenant_id})

    def update_subnet(self, subnet, subnet_update):

        tenant_id = subnet['tenant_id']
        network_id = subnet['network_id']
        subnet_id = subnet['id']

        uri = SUBNET_URI % (tenant_id, network_id, subnet_id)

        self.send_request("PUT", uri,
                          body=jsonutils.dumps(subnet_update),
                          resource='subnet', tenant_id=tenant_id,
                          resource_id=subnet_id)

        LOG.debug("Subnet %(id)s updated under tenant %(tenant_id)s",
                  {'id': subnet_id, 'tenant_id': tenant_id})

    def create_port(self, tenant_id, port):

        network_id = port["network_id"]
        fixed_ips = port.get("fixed_ips")
        ip_address = None
        subnet_id = None

        if fixed_ips:
            ip_address = fixed_ips[0].get("ip_address")
            subnet_id = fixed_ips[0].get("subnet_id")

        lport = {
            "id": port["id"],
            "name": port["name"],
            "device_id": port["device_id"],
            "device_owner": port["device_owner"],
            "mac_address": port["mac_address"],
            "ip_address": ip_address,
            "subnet_id": subnet_id,
            "admin_state_up": port["admin_state_up"],
            "network_id": network_id,
            "status": port["status"]
        }

        path = PORTS_URI % (tenant_id, network_id)

        self.send_request("POST", path, body=jsonutils.dumps(lport),
                          resource='port', tenant_id=tenant_id)

        LOG.debug("Port %(id)s created under tenant %(tenant_id)s",
                  {'id': port['id'], 'tenant_id': tenant_id})

    def update_port(self, tenant_id, port, port_update):

        network_id = port['network_id']
        port_id = port['id']

        lport = {}
        for k in ('admin_state_up', 'name', 'device_id', 'device_owner'):
            if k in port_update:
                lport[k] = port_update[k]

        fixed_ips = port_update.get('fixed_ips', None)
        if fixed_ips:
            lport["ip_address"] = fixed_ips[0].get("ip_address")
            lport["subnet_id"] = fixed_ips[0].get("subnet_id")

        uri = PORT_URI % (tenant_id, network_id, port_id)

        self.send_request("PUT", uri, body=jsonutils.dumps(lport),
                          resource='port', tenant_id=tenant_id,
                          resource_id=port_id)

        LOG.debug("Port %(id)s updated under tenant %(tenant_id)s",
                  {'id': port_id, 'tenant_id': tenant_id})

    def delete_port(self, port_id, port):

        tenant_id = port['tenant_id']
        network_id = port['network_id']

        uri = PORT_URI % (tenant_id, network_id, port_id)

        self.send_request("DELETE", uri, resource='port', tenant_id=tenant_id,
                          resource_id=port_id)

        LOG.debug("Port %(id)s deleted under tenant %(tenant_id)s",
                  {'id': port_id, 'tenant_id': tenant_id})

    def _get_ports(self, tenant_id, network_id):

        uri = PORTS_URI % (tenant_id, network_id)

        response = self.send_request("GET", uri, resource='ports',
                                     tenant_id=tenant_id)

        return response.json()

    def create_floatingip(self, floating_ip):

        tenant_id = floating_ip['tenant_id']

        uri = FLOATING_IPS_URI % tenant_id

        self.send_request("POST", uri, body=jsonutils.dumps(floating_ip),
                          resource='floating_ip',
                          tenant_id=tenant_id)

        LOG.debug("Flatingip %(id)s created under tenant %(tenant_id)s",
                  {'id': floating_ip['id'], 'tenant_id': tenant_id})

    def update_floatingip(self, floating_ip, floating_ip_update):

        tenant_id = floating_ip['tenant_id']

        floating_ip_id = floating_ip['id']

        uri = FLOATING_IP_URI % (tenant_id, floating_ip_id)

        self.send_request("PUT", uri,
                          body=jsonutils.dumps(
                              floating_ip_update['floatingip']),
                          resource='floating_ip',
                          tenant_id=tenant_id,
                          resource_id=floating_ip_id)

        LOG.debug("Flatingip %(id)s updated under tenant %(tenant_id)s",
                  {'id': floating_ip_id, 'tenant_id': tenant_id})

    def delete_floatingip(self, floating_ip):

        tenant_id = floating_ip['tenant_id']

        floating_ip_id = floating_ip['id']

        uri = FLOATING_IP_URI % (tenant_id, floating_ip_id)

        self.send_request("DELETE", uri, resource='floating_ip',
                          tenant_id=tenant_id, resource_id=floating_ip_id)

        LOG.debug("Flatingip %(id)s deleted under tenant %(tenant_id)s",
                  {'id': floating_ip_id, 'tenant_id': tenant_id})

    def create_router(self, router):

        tenant_id = router['tenant_id']

        uri = ROUTERS_URI % tenant_id

        self.send_request("POST", uri, body=jsonutils.dumps(router),
                          resource='router',
                          tenant_id=tenant_id)

        LOG.debug("Router %(id)s created under tenant %(tenant_id)s",
                  {'id': router['id'], 'tenant_id': tenant_id})

    def update_router(self, router):

        tenant_id = router['tenant_id']

        router_id = router['id']

        uri = ROUTER_URI % (tenant_id, router_id)

        self.send_request("PUT", uri,
                          body=jsonutils.dumps(router),
                          resource='router', tenant_id=tenant_id,
                          resource_id=router_id)

        LOG.debug("Router %(id)s updated under tenant %(tenant_id)s",
                  {'id': router_id, 'tenant_id': tenant_id})

    def delete_router(self, tenant_id, router_id):

        uri = ROUTER_URI % (tenant_id, router_id)

        self.send_request("DELETE", uri, resource='router',
                          tenant_id=tenant_id, resource_id=router_id)

        LOG.debug("Router %(id)s deleted under tenant %(tenant_id)s",
                  {'id': router_id, 'tenant_id': tenant_id})
