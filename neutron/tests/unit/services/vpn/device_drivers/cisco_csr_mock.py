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
#
# @author: Paul Michali, Cisco Systems, Inc.

"""Mock REST requests to Cisco Cloud Services Router."""

import re

import functools
# TODO(pcm): Remove when switch to requests-mock package. Comment out, if use
# local copy of httmock.py source. Needed for PEP8.
import httmock
import requests
from requests import exceptions as r_exc

from neutron.openstack.common import log as logging
# TODO(pcm) Remove once httmock package is added to test-requirements. For
# now, uncomment and include httmock source to unit test.
# from neutron.tests.unit.services.vpn.device_drivers import httmock

LOG = logging.getLogger(__name__)


def repeat(n):
    """Decorator to limit the number of times a handler is called.

    Will allow the wrapped function (handler) to be called 'n' times.
    After that, this will return None for any additional calls,
    allowing other handlers, if any, to be invoked.
    """

    class static:
        retries = n

    def decorator(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            if static.retries == 0:
                return None
            static.retries -= 1
            return func(*args, **kwargs)
        return wrapped
    return decorator


def filter_request(methods, resource):
    """Decorator to invoke handler once for a specific resource.

    This will call the handler only for a specific resource using
    a specific method(s). Any other resource request or method will
    return None, allowing other handlers, if any, to be invoked.
    """

    class static:
        target_methods = [m.upper() for m in methods]
        target_resource = resource

    def decorator(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            if (args[1].method in static.target_methods and
                static.target_resource in args[0].path):
                return func(*args, **kwargs)
            else:
                return None  # Not for this resource
        return wrapped
    return decorator


@httmock.urlmatch(netloc=r'localhost')
def token(url, request):
    if 'auth/token-services' in url.path:
        return {'status_code': requests.codes.OK,
                'content': {'token-id': 'dummy-token'}}


@httmock.urlmatch(netloc=r'localhost')
def token_unauthorized(url, request):
    if 'auth/token-services' in url.path:
        return {'status_code': requests.codes.UNAUTHORIZED}


@httmock.urlmatch(netloc=r'wrong-host')
def token_wrong_host(url, request):
    raise r_exc.ConnectionError()


@httmock.all_requests
def token_timeout(url, request):
    raise r_exc.Timeout()


@filter_request(['get'], 'global/host-name')
@httmock.all_requests
def timeout(url, request):
    """Simulated timeout of a normal request."""

    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    raise r_exc.Timeout()


@httmock.urlmatch(netloc=r'localhost')
def no_such_resource(url, request):
    """Indicate not found error, when invalid resource requested."""
    return {'status_code': requests.codes.NOT_FOUND}


@filter_request(['get'], 'global/host-name')
@repeat(1)
@httmock.urlmatch(netloc=r'localhost')
def expired_request(url, request):
    """Simulate access denied failure on first request for this resource.

    Intent here is to simulate that the token has expired, by failing
    the first request to the resource. Because of the repeat=1, this
    will only be called once, and subsequent calls will not be handled
    by this function, but instead will access the normal handler and
    will pass. Currently configured for a GET request, but will work
    with POST and PUT as well. For DELETE, would need to filter_request on a
    different resource (e.g. 'global/local-users')
    """

    return {'status_code': requests.codes.UNAUTHORIZED}


@httmock.urlmatch(netloc=r'localhost')
def normal_get(url, request):
    if request.method != 'GET':
        return
    LOG.debug("GET mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    if 'global/host-name' in url.path:
        content = {u'kind': u'object#host-name',
                   u'host-name': u'Router'}
        return httmock.response(requests.codes.OK, content=content)
    if 'global/local-users' in url.path:
        content = {u'kind': u'collection#local-user',
                   u'users': ['peter', 'paul', 'mary']}
        return httmock.response(requests.codes.OK, content=content)
    if 'interfaces/GigabitEthernet' in url.path:
        actual_interface = url.path.split('/')[-1]
        ip = actual_interface[-1]
        content = {u'kind': u'object#interface',
                   u'description': u'Changed description',
                   u'if-name': actual_interface,
                   u'proxy-arp': True,
                   u'subnet-mask': u'255.255.255.0',
                   u'icmp-unreachable': True,
                   u'nat-direction': u'',
                   u'icmp-redirects': True,
                   u'ip-address': u'192.168.200.%s' % ip,
                   u'verify-unicast-source': False,
                   u'type': u'ethernet'}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/ike/policies/2' in url.path:
        content = {u'kind': u'object#ike-policy',
                   u'priority-id': u'2',
                   u'version': u'v1',
                   u'local-auth-method': u'pre-share',
                   u'encryption': u'aes256',
                   u'hash': u'sha',
                   u'dhGroup': 5,
                   u'lifetime': 3600}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/ike/keyrings' in url.path:
        content = {u'kind': u'object#ike-keyring',
                   u'keyring-name': u'5',
                   u'pre-shared-key-list': [
                       {u'key': u'super-secret',
                        u'encrypted': False,
                        u'peer-address': u'10.10.10.20 255.255.255.0'}
                   ]}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/ipsec/policies/' in url.path:
        ipsec_policy_id = url.path.split('/')[-1]
        content = {u'kind': u'object#ipsec-policy',
                   u'mode': u'tunnel',
                   u'policy-id': u'%s' % ipsec_policy_id,
                   u'protection-suite': {
                       u'esp-encryption': u'esp-256-aes',
                       u'esp-authentication': u'esp-sha-hmac',
                       u'ah': u'ah-sha-hmac',
                   },
                   u'anti-replay-window-size': u'Disable',
                   u'lifetime-sec': 120,
                   u'pfs': u'group5',
                   u'lifetime-kb': 4608000,
                   u'idle-time': None}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/site-to-site/Tunnel' in url.path:
        tunnel = url.path.split('/')[-1]
        # Use same number, to allow mock to generate IPSec policy ID
        ipsec_policy_id = tunnel[6:]
        content = {u'kind': u'object#vpn-site-to-site',
                   u'vpn-interface-name': u'%s' % tunnel,
                   u'ip-version': u'ipv4',
                   u'vpn-type': u'site-to-site',
                   u'ipsec-policy-id': u'%s' % ipsec_policy_id,
                   u'ike-profile-id': None,
                   u'mtu': 1500,
                   u'local-device': {
                       u'ip-address': '10.3.0.1/24',
                       u'tunnel-ip-address': '10.10.10.10'
                   },
                   u'remote-device': {
                       u'tunnel-ip-address': '10.10.10.20'
                   }}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/ike/keepalive' in url.path:
        content = {u'interval': 60,
                   u'retry': 4,
                   u'periodic': True}
        return httmock.response(requests.codes.OK, content=content)
    if 'routing-svc/static-routes' in url.path:
        content = {u'destination-network': u'10.1.0.0/24',
                   u'kind': u'object#static-route',
                   u'next-hop-router': None,
                   u'outgoing-interface': u'GigabitEthernet1',
                   u'admin-distance': 1}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/site-to-site/active/sessions' in url.path:
        # Only including needed fields for mock
        content = {u'kind': u'collection#vpn-active-sessions',
                   u'items': [{u'status': u'DOWN-NEGOTIATING',
                               u'vpn-interface-name': u'Tunnel123'}, ]}
        return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/ike/keyrings')
@httmock.urlmatch(netloc=r'localhost')
def get_fqdn(url, request):
    LOG.debug("GET FQDN mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    content = {u'kind': u'object#ike-keyring',
               u'keyring-name': u'5',
               u'pre-shared-key-list': [
                   {u'key': u'super-secret',
                    u'encrypted': False,
                    u'peer-address': u'cisco.com'}
               ]}
    return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/ipsec/policies/')
@httmock.urlmatch(netloc=r'localhost')
def get_no_ah(url, request):
    LOG.debug("GET No AH mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    ipsec_policy_id = url.path.split('/')[-1]
    content = {u'kind': u'object#ipsec-policy',
               u'mode': u'tunnel',
               u'anti-replay-window-size': u'128',
               u'policy-id': u'%s' % ipsec_policy_id,
               u'protection-suite': {
                   u'esp-encryption': u'esp-aes',
                   u'esp-authentication': u'esp-sha-hmac',
               },
               u'lifetime-sec': 120,
               u'pfs': u'group5',
               u'lifetime-kb': 4608000,
               u'idle-time': None}
    return httmock.response(requests.codes.OK, content=content)


@httmock.urlmatch(netloc=r'localhost')
def get_defaults(url, request):
    if request.method != 'GET':
        return
    LOG.debug("GET mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    if 'vpn-svc/ike/policies/2' in url.path:
        content = {u'kind': u'object#ike-policy',
                   u'priority-id': u'2',
                   u'version': u'v1',
                   u'local-auth-method': u'pre-share',
                   u'encryption': u'des',
                   u'hash': u'sha',
                   u'dhGroup': 1,
                   u'lifetime': 86400}
        return httmock.response(requests.codes.OK, content=content)
    if 'vpn-svc/ipsec/policies/' in url.path:
        ipsec_policy_id = url.path.split('/')[-1]
        content = {u'kind': u'object#ipsec-policy',
                   u'mode': u'tunnel',
                   u'policy-id': u'%s' % ipsec_policy_id,
                   u'protection-suite': {},
                   u'lifetime-sec': 3600,
                   u'pfs': u'Disable',
                   u'anti-replay-window-size': u'None',
                   u'lifetime-kb': 4608000,
                   u'idle-time': None}
        return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/site-to-site')
@httmock.urlmatch(netloc=r'localhost')
def get_unnumbered(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    tunnel = url.path.split('/')[-1]
    ipsec_policy_id = tunnel[6:]
    content = {u'kind': u'object#vpn-site-to-site',
               u'vpn-interface-name': u'%s' % tunnel,
               u'ip-version': u'ipv4',
               u'vpn-type': u'site-to-site',
               u'ipsec-policy-id': u'%s' % ipsec_policy_id,
               u'ike-profile-id': None,
               u'mtu': 1500,
               u'local-device': {
                   u'ip-address': u'GigabitEthernet3',
                   u'tunnel-ip-address': u'10.10.10.10'
               },
               u'remote-device': {
                   u'tunnel-ip-address': u'10.10.10.20'
               }}
    return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/site-to-site/Tunnel')
@httmock.urlmatch(netloc=r'localhost')
def get_admin_down(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    # URI has .../Tunnel#/state, so get number from 2nd to last element
    tunnel = url.path.split('/')[-2]
    content = {u'kind': u'object#vpn-site-to-site-state',
               u'vpn-interface-name': u'%s' % tunnel,
               u'line-protocol-state': u'down',
               u'enabled': False}
    return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/site-to-site/Tunnel')
@httmock.urlmatch(netloc=r'localhost')
def get_admin_up(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    # URI has .../Tunnel#/state, so get number from 2nd to last element
    tunnel = url.path.split('/')[-2]
    content = {u'kind': u'object#vpn-site-to-site-state',
               u'vpn-interface-name': u'%s' % tunnel,
               u'line-protocol-state': u'down',
               u'enabled': True}
    return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/site-to-site')
@httmock.urlmatch(netloc=r'localhost')
def get_mtu(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    tunnel = url.path.split('/')[-1]
    ipsec_policy_id = tunnel[6:]
    content = {u'kind': u'object#vpn-site-to-site',
               u'vpn-interface-name': u'%s' % tunnel,
               u'ip-version': u'ipv4',
               u'vpn-type': u'site-to-site',
               u'ipsec-policy-id': u'%s' % ipsec_policy_id,
               u'ike-profile-id': None,
               u'mtu': 9192,
               u'local-device': {
                   u'ip-address': u'10.3.0.1/24',
                   u'tunnel-ip-address': u'10.10.10.10'
               },
               u'remote-device': {
                   u'tunnel-ip-address': u'10.10.10.20'
               }}
    return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'vpn-svc/ike/keepalive')
@httmock.urlmatch(netloc=r'localhost')
def get_not_configured(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.NOT_FOUND}


@filter_request(['get'], 'vpn-svc/site-to-site/active/sessions')
@httmock.urlmatch(netloc=r'localhost')
def get_none(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    content = {u'kind': u'collection#vpn-active-sessions',
               u'items': []}
    return httmock.response(requests.codes.OK, content=content)


@filter_request(['get'], 'interfaces/GigabitEthernet3')
@httmock.urlmatch(netloc=r'localhost')
def get_local_ip(url, request):
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    content = {u'kind': u'object#interface',
               u'subnet-mask': u'255.255.255.0',
               u'ip-address': u'10.5.0.2'}
    return httmock.response(requests.codes.OK, content=content)


@httmock.urlmatch(netloc=r'localhost')
def post(url, request):
    if request.method != 'POST':
        return
    LOG.debug("POST mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    if 'interfaces/GigabitEthernet' in url.path:
        return {'status_code': requests.codes.NO_CONTENT}
    if 'global/local-users' in url.path:
        if 'username' not in request.body:
            return {'status_code': requests.codes.BAD_REQUEST}
        if '"privilege": 20' in request.body:
            return {'status_code': requests.codes.BAD_REQUEST}
        headers = {'location': '%s/test-user' % url.geturl()}
        return httmock.response(requests.codes.CREATED, headers=headers)
    if 'vpn-svc/ike/policies' in url.path:
        headers = {'location': "%s/2" % url.geturl()}
        return httmock.response(requests.codes.CREATED, headers=headers)
    if 'vpn-svc/ipsec/policies' in url.path:
        m = re.search(r'"policy-id": "(\S+)"', request.body)
        if m:
            headers = {'location': "%s/%s" % (url.geturl(), m.group(1))}
            return httmock.response(requests.codes.CREATED, headers=headers)
        return {'status_code': requests.codes.BAD_REQUEST}
    if 'vpn-svc/ike/keyrings' in url.path:
        headers = {'location': "%s/5" % url.geturl()}
        return httmock.response(requests.codes.CREATED, headers=headers)
    if 'vpn-svc/site-to-site' in url.path:
        m = re.search(r'"vpn-interface-name": "(\S+)"', request.body)
        if m:
            headers = {'location': "%s/%s" % (url.geturl(), m.group(1))}
            return httmock.response(requests.codes.CREATED, headers=headers)
        return {'status_code': requests.codes.BAD_REQUEST}
    if 'routing-svc/static-routes' in url.path:
        headers = {'location':
                   "%s/10.1.0.0_24_GigabitEthernet1" % url.geturl()}
        return httmock.response(requests.codes.CREATED, headers=headers)


@filter_request(['post'], 'global/local-users')
@httmock.urlmatch(netloc=r'localhost')
def post_change_attempt(url, request):
    LOG.debug("POST change value mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.NOT_FOUND,
            'content': {
                u'error-code': -1,
                u'error-message': u'user test-user already exists'}}


@httmock.urlmatch(netloc=r'localhost')
def post_duplicate(url, request):
    LOG.debug("POST duplicate mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST,
            'content': {
                u'error-code': -1,
                u'error-message': u'policy 2 exist, not allow to '
                                  u'update policy using POST method'}}


@filter_request(['post'], 'vpn-svc/site-to-site')
@httmock.urlmatch(netloc=r'localhost')
def post_missing_ipsec_policy(url, request):
    LOG.debug("POST missing ipsec policy mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST}


@filter_request(['post'], 'vpn-svc/site-to-site')
@httmock.urlmatch(netloc=r'localhost')
def post_missing_ike_policy(url, request):
    LOG.debug("POST missing ike policy mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST}


@filter_request(['post'], 'vpn-svc/site-to-site')
@httmock.urlmatch(netloc=r'localhost')
def post_bad_ip(url, request):
    LOG.debug("POST bad IP mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST}


@filter_request(['post'], 'vpn-svc/site-to-site')
@httmock.urlmatch(netloc=r'localhost')
def post_bad_mtu(url, request):
    LOG.debug("POST bad mtu mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST}


@filter_request(['post'], 'vpn-svc/ipsec/policies')
@httmock.urlmatch(netloc=r'localhost')
def post_bad_lifetime(url, request):
    LOG.debug("POST bad lifetime mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST}


@filter_request(['post'], 'vpn-svc/ipsec/policies')
@httmock.urlmatch(netloc=r'localhost')
def post_bad_name(url, request):
    LOG.debug("POST bad IPSec policy name for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    return {'status_code': requests.codes.BAD_REQUEST}


@httmock.urlmatch(netloc=r'localhost')
def put(url, request):
    if request.method != 'PUT':
        return
    LOG.debug("PUT mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    # Any resource
    return {'status_code': requests.codes.NO_CONTENT}


@httmock.urlmatch(netloc=r'localhost')
def delete(url, request):
    if request.method != 'DELETE':
        return
    LOG.debug("DELETE mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    # Any resource
    return {'status_code': requests.codes.NO_CONTENT}


@httmock.urlmatch(netloc=r'localhost')
def delete_unknown(url, request):
    if request.method != 'DELETE':
        return
    LOG.debug("DELETE unknown mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    # Any resource
    return {'status_code': requests.codes.NOT_FOUND,
            'content': {
                u'error-code': -1,
                u'error-message': 'user unknown not found'}}


@httmock.urlmatch(netloc=r'localhost')
def delete_not_allowed(url, request):
    if request.method != 'DELETE':
        return
    LOG.debug("DELETE not allowed mock for %s", url)
    if not request.headers.get('X-auth-token', None):
        return {'status_code': requests.codes.UNAUTHORIZED}
    # Any resource
    return {'status_code': requests.codes.METHOD_NOT_ALLOWED}
