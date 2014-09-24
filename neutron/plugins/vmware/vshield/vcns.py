# Copyright 2013 VMware, Inc
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

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.vshield.common import VcnsApiClient

LOG = logging.getLogger(__name__)

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"
URI_PREFIX = "/api/4.0/edges"

#FwaaS constants
FIREWALL_SERVICE = "firewall/config"
FIREWALL_RULE_RESOURCE = "rules"

#LbaaS Constants
LOADBALANCER_SERVICE = "loadbalancer/config"
VIP_RESOURCE = "virtualservers"
POOL_RESOURCE = "pools"
MONITOR_RESOURCE = "monitors"
APP_PROFILE_RESOURCE = "applicationprofiles"

# IPsec VPNaaS Constants
IPSEC_VPN_SERVICE = 'ipsec/config'


class Vcns(object):

    def __init__(self, address, user, password):
        self.address = address
        self.user = user
        self.password = password
        self.jsonapi_client = VcnsApiClient.VcnsApiHelper(address, user,
                                                          password, 'json')

    def do_request(self, method, uri, params=None, format='json', **kwargs):
        LOG.debug("VcnsApiHelper('%(method)s', '%(uri)s', '%(body)s')", {
                  'method': method,
                  'uri': uri,
                  'body': jsonutils.dumps(params)})
        if format == 'json':
            header, content = self.jsonapi_client.request(method, uri, params)
        else:
            header, content = self.xmlapi_client.request(method, uri, params)
        LOG.debug("Header: '%s'", header)
        LOG.debug("Content: '%s'", content)
        if content == '':
            return header, {}
        if kwargs.get('decode', True):
            content = jsonutils.loads(content)
        return header, content

    def deploy_edge(self, request):
        uri = URI_PREFIX + "?async=true"
        return self.do_request(HTTP_POST, uri, request, decode=False)

    def get_edge_id(self, job_id):
        uri = URI_PREFIX + "/jobs/%s" % job_id
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_edge_deploy_status(self, edge_id):
        uri = URI_PREFIX + "/%s/status?getlatest=false" % edge_id
        return self.do_request(HTTP_GET, uri, decode="True")

    def delete_edge(self, edge_id):
        uri = "%s/%s" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_DELETE, uri)

    def update_interface(self, edge_id, vnic):
        uri = "%s/%s/vnics/%d" % (URI_PREFIX, edge_id, vnic['index'])
        return self.do_request(HTTP_PUT, uri, vnic, decode=True)

    def get_nat_config(self, edge_id):
        uri = "%s/%s/nat/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_nat_config(self, edge_id, nat):
        uri = "%s/%s/nat/config" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_PUT, uri, nat, decode=True)

    def delete_nat_rule(self, edge_id, rule_id):
        uri = "%s/%s/nat/config/rules/%s" % (URI_PREFIX, edge_id, rule_id)
        return self.do_request(HTTP_DELETE, uri, decode=True)

    def get_edge_status(self, edge_id):
        uri = "%s/%s/status?getlatest=false" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_edges(self):
        uri = URI_PREFIX
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_routes(self, edge_id, routes):
        uri = "%s/%s/routing/config/static" % (URI_PREFIX, edge_id)
        return self.do_request(HTTP_PUT, uri, routes)

    def create_lswitch(self, lsconfig):
        uri = "/api/ws.v1/lswitch"
        return self.do_request(HTTP_POST, uri, lsconfig, decode=True)

    def delete_lswitch(self, lswitch_id):
        uri = "/api/ws.v1/lswitch/%s" % lswitch_id
        return self.do_request(HTTP_DELETE, uri)

    def get_loadbalancer_config(self, edge_id):
        uri = self._build_uri_path(edge_id, LOADBALANCER_SERVICE)
        return self.do_request(HTTP_GET, uri, decode=True)

    def enable_service_loadbalancer(self, edge_id, config):
        uri = self._build_uri_path(edge_id, LOADBALANCER_SERVICE)
        return self.do_request(HTTP_PUT, uri, config)

    def update_firewall(self, edge_id, fw_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE)
        return self.do_request(HTTP_PUT, uri, fw_req)

    def delete_firewall(self, edge_id):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE, None)
        return self.do_request(HTTP_DELETE, uri)

    def update_firewall_rule(self, edge_id, vcns_rule_id, fwr_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE,
            vcns_rule_id)
        return self.do_request(HTTP_PUT, uri, fwr_req)

    def delete_firewall_rule(self, edge_id, vcns_rule_id):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE,
            vcns_rule_id)
        return self.do_request(HTTP_DELETE, uri)

    def add_firewall_rule_above(self, edge_id, ref_vcns_rule_id, fwr_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE)
        uri += "?aboveRuleId=" + ref_vcns_rule_id
        return self.do_request(HTTP_POST, uri, fwr_req)

    def add_firewall_rule(self, edge_id, fwr_req):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE)
        return self.do_request(HTTP_POST, uri, fwr_req)

    def get_firewall(self, edge_id):
        uri = self._build_uri_path(edge_id, FIREWALL_SERVICE)
        return self.do_request(HTTP_GET, uri, decode=True)

    def get_firewall_rule(self, edge_id, vcns_rule_id):
        uri = self._build_uri_path(
            edge_id, FIREWALL_SERVICE,
            FIREWALL_RULE_RESOURCE,
            vcns_rule_id)
        return self.do_request(HTTP_GET, uri, decode=True)

    #
    #Edge LBAAS call helper
    #
    def create_vip(self, edge_id, vip_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE)
        return self.do_request(HTTP_POST, uri, vip_new)

    def get_vip(self, edge_id, vip_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE, vip_vseid)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_vip(self, edge_id, vip_vseid, vip_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE, vip_vseid)
        return self.do_request(HTTP_PUT, uri, vip_new)

    def delete_vip(self, edge_id, vip_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            VIP_RESOURCE, vip_vseid)
        return self.do_request(HTTP_DELETE, uri)

    def create_pool(self, edge_id, pool_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE)
        return self.do_request(HTTP_POST, uri, pool_new)

    def get_pool(self, edge_id, pool_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE, pool_vseid)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_pool(self, edge_id, pool_vseid, pool_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE, pool_vseid)
        return self.do_request(HTTP_PUT, uri, pool_new)

    def delete_pool(self, edge_id, pool_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            POOL_RESOURCE, pool_vseid)
        return self.do_request(HTTP_DELETE, uri)

    def create_health_monitor(self, edge_id, monitor_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE)
        return self.do_request(HTTP_POST, uri, monitor_new)

    def get_health_monitor(self, edge_id, monitor_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE, monitor_vseid)
        return self.do_request(HTTP_GET, uri, decode=True)

    def update_health_monitor(self, edge_id, monitor_vseid, monitor_new):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE,
            monitor_vseid)
        return self.do_request(HTTP_PUT, uri, monitor_new)

    def delete_health_monitor(self, edge_id, monitor_vseid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            MONITOR_RESOURCE,
            monitor_vseid)
        return self.do_request(HTTP_DELETE, uri)

    def create_app_profile(self, edge_id, app_profile):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_PROFILE_RESOURCE)
        return self.do_request(HTTP_POST, uri, app_profile)

    def update_app_profile(self, edge_id, app_profileid, app_profile):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_PROFILE_RESOURCE, app_profileid)
        return self.do_request(HTTP_PUT, uri, app_profile)

    def delete_app_profile(self, edge_id, app_profileid):
        uri = self._build_uri_path(
            edge_id, LOADBALANCER_SERVICE,
            APP_PROFILE_RESOURCE,
            app_profileid)
        return self.do_request(HTTP_DELETE, uri)

    def update_ipsec_config(self, edge_id, ipsec_config):
        uri = self._build_uri_path(edge_id, IPSEC_VPN_SERVICE)
        return self.do_request(HTTP_PUT, uri, ipsec_config)

    def delete_ipsec_config(self, edge_id):
        uri = self._build_uri_path(edge_id, IPSEC_VPN_SERVICE)
        return self.do_request(HTTP_DELETE, uri)

    def get_ipsec_config(self, edge_id):
        uri = self._build_uri_path(edge_id, IPSEC_VPN_SERVICE)
        return self.do_request(HTTP_GET, uri)

    def _build_uri_path(self, edge_id,
                        service,
                        resource=None,
                        resource_id=None,
                        parent_resource_id=None,
                        fields=None,
                        relations=None,
                        filters=None,
                        types=None,
                        is_attachment=False):
        uri_prefix = "%s/%s/%s" % (URI_PREFIX, edge_id, service)
        if resource:
            res_path = resource + (resource_id and "/%s" % resource_id or '')
            uri_path = "%s/%s" % (uri_prefix, res_path)
        else:
            uri_path = uri_prefix
        return uri_path
