# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
#
# @author: linb, VMware

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.nicira.vshield.common import VcnsApiClient

LOG = logging.getLogger(__name__)

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"
URI_PREFIX = "/api/4.0/edges"


class Vcns(object):

    def __init__(self, address, user, password):
        self.address = address
        self.user = user
        self.password = password
        self.jsonapi_client = VcnsApiClient.VcnsApiHelper(address, user,
                                                          password, 'json')

    def do_request(self, method, uri, params=None, format='json', **kwargs):
        LOG.debug(_("VcnsApiHelper('%(method)s', '%(uri)s', '%(body)s')"), {
                  'method': method,
                  'uri': uri,
                  'body': jsonutils.dumps(params)})
        if format == 'json':
            header, content = self.jsonapi_client.request(method, uri, params)
        else:
            header, content = self.xmlapi_client.request(method, uri, params)
        LOG.debug(_("Header: '%s'"), header)
        LOG.debug(_("Content: '%s'"), content)
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
