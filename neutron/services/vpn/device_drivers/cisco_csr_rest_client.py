# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import time

import netaddr
import requests
from requests import exceptions as r_exc

from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging


TIMEOUT = 20.0

LOG = logging.getLogger(__name__)
HEADER_CONTENT_TYPE_JSON = {'content-type': 'application/json'}
URL_BASE = 'https://%(host)s/api/v1/%(resource)s'

# CSR RESTapi URIs

URI_VPN_IPSEC_POLICIES = 'vpn-svc/ipsec/policies'
URI_VPN_IPSEC_POLICIES_ID = URI_VPN_IPSEC_POLICIES + '/%s'
URI_VPN_IKE_POLICIES = 'vpn-svc/ike/policies'
URI_VPN_IKE_POLICIES_ID = URI_VPN_IKE_POLICIES + '/%s'
URI_VPN_IKE_KEYRINGS = 'vpn-svc/ike/keyrings'
URI_VPN_IKE_KEYRINGS_ID = URI_VPN_IKE_KEYRINGS + '/%s'
URI_VPN_IKE_KEEPALIVE = 'vpn-svc/ike/keepalive'
URI_VPN_SITE_TO_SITE = 'vpn-svc/site-to-site'
URI_VPN_SITE_TO_SITE_ID = URI_VPN_SITE_TO_SITE + '/%s'
URI_VPN_SITE_TO_SITE_STATE = URI_VPN_SITE_TO_SITE + '/%s/state'
URI_VPN_SITE_ACTIVE_SESSIONS = URI_VPN_SITE_TO_SITE + '/active/sessions'
URI_ROUTING_STATIC_ROUTES = 'routing-svc/static-routes'
URI_ROUTING_STATIC_ROUTES_ID = URI_ROUTING_STATIC_ROUTES + '/%s'


def make_route_id(cidr, interface):
    """Build ID that will be used to identify route for later deletion."""
    net = netaddr.IPNetwork(cidr)
    return '%(network)s_%(prefix)s_%(interface)s' % {
        'network': net.network,
        'prefix': net.prefixlen,
        'interface': interface}


class CsrRestClient(object):

    """REST CsrRestClient for accessing the Cisco Cloud Services Router."""

    def __init__(self, settings):
        self.port = str(settings.get('protocol_port', 55443))
        self.host = ':'.join([settings.get('rest_mgmt_ip', ''), self.port])
        self.tunnel_ip = settings.get('external_ip', '')
        self.auth = (settings['username'], settings['password'])
        self.tunnel_if_name = settings.get('tunnel_if_name', '')
        self.token = None
        self.status = requests.codes.OK
        self.timeout = settings.get('timeout')
        self.max_tries = 5
        self.session = requests.Session()

    def _response_info_for(self, response, method):
        """Return contents or location from response.

        For a POST or GET with a 200 response, the response content
        is returned.

        For a POST with a 201 response, return the header's location,
        which contains the identifier for the created resource.

        If there is an error, return the response content, so that
        it can be used in error processing ('error-code', 'error-message',
        and 'detail' fields).
        """
        if method in ('POST', 'GET') and self.status == requests.codes.OK:
            LOG.debug(_('RESPONSE: %s'), response.json())
            return response.json()
        if method == 'POST' and self.status == requests.codes.CREATED:
            return response.headers.get('location', '')
        if self.status >= requests.codes.BAD_REQUEST and response.content:
            if 'error-code' in response.content:
                content = jsonutils.loads(response.content)
                LOG.debug("Error response content %s", content)
                return content

    def _request(self, method, url, **kwargs):
        """Perform REST request and save response info."""
        try:
            LOG.debug(_("%(method)s: Request for %(resource)s payload: "
                        "%(payload)s"),
                      {'method': method.upper(), 'resource': url,
                       'payload': kwargs.get('data')})
            start_time = time.time()
            response = self.session.request(method, url, verify=False,
                                            timeout=self.timeout, **kwargs)
            LOG.debug(_("%(method)s Took %(time).2f seconds to process"),
                      {'method': method.upper(),
                       'time': time.time() - start_time})
        except (r_exc.Timeout, r_exc.SSLError) as te:
            # Should never see SSLError, unless requests package is old (<2.0)
            timeout_val = 0.0 if self.timeout is None else self.timeout
            LOG.warning(_("%(method)s: Request timeout%(ssl)s "
                          "(%(timeout).3f sec) for CSR(%(host)s)"),
                        {'method': method,
                         'timeout': timeout_val,
                         'ssl': '(SSLError)'
                         if isinstance(te, r_exc.SSLError) else '',
                         'host': self.host})
            self.status = requests.codes.REQUEST_TIMEOUT
        except r_exc.ConnectionError:
            LOG.exception(_("%(method)s: Unable to connect to CSR(%(host)s)"),
                          {'method': method, 'host': self.host})
            self.status = requests.codes.NOT_FOUND
        except Exception as e:
            LOG.error(_("%(method)s: Unexpected error for CSR (%(host)s): "
                        "%(error)s"),
                      {'method': method, 'host': self.host, 'error': e})
            self.status = requests.codes.INTERNAL_SERVER_ERROR
        else:
            self.status = response.status_code
            LOG.debug(_("%(method)s: Completed [%(status)s]"),
                      {'method': method, 'status': self.status})
            return self._response_info_for(response, method)

    def authenticate(self):
        """Obtain a token to use for subsequent CSR REST requests.

        This is called when there is no token yet, or if the token has expired
        and attempts to use it resulted in an UNAUTHORIZED REST response.
        """

        url = URL_BASE % {'host': self.host, 'resource': 'auth/token-services'}
        headers = {'Content-Length': '0',
                   'Accept': 'application/json'}
        headers.update(HEADER_CONTENT_TYPE_JSON)
        LOG.debug(_("%(auth)s with CSR %(host)s"),
                  {'auth': 'Authenticating' if self.token is None
                   else 'Reauthenticating', 'host': self.host})
        self.token = None
        response = self._request("POST", url, headers=headers, auth=self.auth)
        if response:
            self.token = response['token-id']
            LOG.debug(_("Successfully authenticated with CSR %s"), self.host)
            return True
        LOG.error(_("Failed authentication with CSR %(host)s [%(status)s]"),
                  {'host': self.host, 'status': self.status})

    def _do_request(self, method, resource, payload=None, more_headers=None,
                    full_url=False):
        """Perform a REST request to a CSR resource.

        If this is the first time interacting with the CSR, a token will
        be obtained. If the request fails, due to an expired token, the
        token will be obtained and the request will be retried once more.
        """

        if self.token is None:
            if not self.authenticate():
                return

        if full_url:
            url = resource
        else:
            url = ('https://%(host)s/api/v1/%(resource)s' %
                   {'host': self.host, 'resource': resource})
        headers = {'Accept': 'application/json', 'X-auth-token': self.token}
        if more_headers:
            headers.update(more_headers)
        if payload:
            payload = jsonutils.dumps(payload)
        response = self._request(method, url, data=payload, headers=headers)
        if self.status == requests.codes.UNAUTHORIZED:
            if not self.authenticate():
                return
            headers['X-auth-token'] = self.token
            response = self._request(method, url, data=payload,
                                     headers=headers)
        if self.status != requests.codes.REQUEST_TIMEOUT:
            return response
        LOG.error(_("%(method)s: Request timeout for CSR(%(host)s)"),
                  {'method': method, 'host': self.host})

    def get_request(self, resource, full_url=False):
        """Perform a REST GET requests for a CSR resource."""
        return self._do_request('GET', resource, full_url=full_url)

    def post_request(self, resource, payload=None):
        """Perform a POST request to a CSR resource."""
        return self._do_request('POST', resource, payload=payload,
                                more_headers=HEADER_CONTENT_TYPE_JSON)

    def put_request(self, resource, payload=None):
        """Perform a PUT request to a CSR resource."""
        return self._do_request('PUT', resource, payload=payload,
                                more_headers=HEADER_CONTENT_TYPE_JSON)

    def delete_request(self, resource):
        """Perform a DELETE request on a CSR resource."""
        return self._do_request('DELETE', resource,
                                more_headers=HEADER_CONTENT_TYPE_JSON)

    def create_ike_policy(self, policy_info):
        base_ike_policy_info = {u'version': u'v1',
                                u'local-auth-method': u'pre-share'}
        base_ike_policy_info.update(policy_info)
        return self.post_request(URI_VPN_IKE_POLICIES,
                                 payload=base_ike_policy_info)

    def create_ipsec_policy(self, policy_info):
        base_ipsec_policy_info = {u'mode': u'tunnel'}
        base_ipsec_policy_info.update(policy_info)
        return self.post_request(URI_VPN_IPSEC_POLICIES,
                                 payload=base_ipsec_policy_info)

    def create_pre_shared_key(self, psk_info):
        return self.post_request(URI_VPN_IKE_KEYRINGS, payload=psk_info)

    def create_ipsec_connection(self, connection_info):
        base_conn_info = {
            u'vpn-type': u'site-to-site',
            u'ip-version': u'ipv4',
            u'local-device': {
                u'tunnel-ip-address': self.tunnel_ip,
                u'ip-address': self.tunnel_if_name
            }
        }
        connection_info.update(base_conn_info)
        return self.post_request(URI_VPN_SITE_TO_SITE,
                                 payload=connection_info)

    def configure_ike_keepalive(self, keepalive_info):
        base_keepalive_info = {u'periodic': True}
        keepalive_info.update(base_keepalive_info)
        return self.put_request(URI_VPN_IKE_KEEPALIVE, keepalive_info)

    def create_static_route(self, route_info):
        return self.post_request(URI_ROUTING_STATIC_ROUTES,
                                 payload=route_info)

    def delete_static_route(self, route_id):
        return self.delete_request(URI_ROUTING_STATIC_ROUTES_ID % route_id)

    def set_ipsec_connection_state(self, tunnel, admin_up=True):
        """Set the IPSec site-to-site connection (tunnel) admin state.

        Note: When a tunnel is created, it will be admin up.
        """
        info = {u'vpn-interface-name': tunnel, u'enabled': admin_up}
        return self.put_request(URI_VPN_SITE_TO_SITE_STATE % tunnel, info)

    def delete_ipsec_connection(self, conn_id):
        return self.delete_request(URI_VPN_SITE_TO_SITE_ID % conn_id)

    def delete_ipsec_policy(self, policy_id):
        return self.delete_request(URI_VPN_IPSEC_POLICIES_ID % policy_id)

    def delete_ike_policy(self, policy_id):
        return self.delete_request(URI_VPN_IKE_POLICIES_ID % policy_id)

    def delete_pre_shared_key(self, key_id):
        return self.delete_request(URI_VPN_IKE_KEYRINGS_ID % key_id)

    def read_tunnel_statuses(self):
        results = self.get_request(URI_VPN_SITE_ACTIVE_SESSIONS)
        if self.status != requests.codes.OK or not results:
            return []
        tunnels = [(t[u'vpn-interface-name'], t[u'status'])
                   for t in results['items']]
        return tunnels
