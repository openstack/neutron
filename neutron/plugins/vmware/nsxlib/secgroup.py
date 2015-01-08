# Copyright 2014 VMware, Inc.
# All Rights Reserved
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

from oslo_serialization import jsonutils
from oslo_utils import excutils

from neutron.common import constants
from neutron.common import exceptions
from neutron.i18n import _LW
from neutron.openstack.common import log
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

SECPROF_RESOURCE = "security-profile"

LOG = log.getLogger(__name__)


def mk_body(**kwargs):
    """Convenience function creates and dumps dictionary to string.

    :param kwargs: the key/value pirs to be dumped into a json string.
    :returns: a json string.
    """
    return jsonutils.dumps(kwargs, ensure_ascii=False)


def query_security_profiles(cluster, fields=None, filters=None):
    return nsxlib.get_all_query_pages(
        nsxlib._build_uri_path(SECPROF_RESOURCE,
                               fields=fields,
                               filters=filters),
        cluster)


def create_security_profile(cluster, tenant_id, neutron_id, security_profile):
    """Create a security profile on the NSX backend.

    :param cluster: a NSX cluster object reference
    :param tenant_id: identifier of the Neutron tenant
    :param neutron_id: neutron security group identifier
    :param security_profile: dictionary with data for
    configuring the NSX security profile.
    """
    path = "/ws.v1/security-profile"
    # Allow all dhcp responses and all ingress traffic
    hidden_rules = {'logical_port_egress_rules':
                    [{'ethertype': 'IPv4',
                      'protocol': constants.PROTO_NUM_UDP,
                      'port_range_min': constants.DHCP_RESPONSE_PORT,
                      'port_range_max': constants.DHCP_RESPONSE_PORT,
                      'ip_prefix': '0.0.0.0/0'}],
                    'logical_port_ingress_rules':
                    [{'ethertype': 'IPv4'},
                     {'ethertype': 'IPv6'}]}
    display_name = utils.check_and_truncate(security_profile.get('name'))
    # NOTE(salv-orlando): neutron-id tags are prepended with 'q' for
    # historical reasons
    body = mk_body(
        tags=utils.get_tags(os_tid=tenant_id, q_sec_group_id=neutron_id),
        display_name=display_name,
        logical_port_ingress_rules=(
            hidden_rules['logical_port_ingress_rules']),
        logical_port_egress_rules=hidden_rules['logical_port_egress_rules']
    )
    rsp = nsxlib.do_request(HTTP_POST, path, body, cluster=cluster)
    if security_profile.get('name') == 'default':
        # If security group is default allow ip traffic between
        # members of the same security profile is allowed and ingress traffic
        # from the switch
        rules = {'logical_port_egress_rules': [{'ethertype': 'IPv4',
                                                'profile_uuid': rsp['uuid']},
                                               {'ethertype': 'IPv6',
                                                'profile_uuid': rsp['uuid']}],
                 'logical_port_ingress_rules': [{'ethertype': 'IPv4'},
                                                {'ethertype': 'IPv6'}]}

        update_security_group_rules(cluster, rsp['uuid'], rules)
    LOG.debug("Created Security Profile: %s", rsp)
    return rsp


def update_security_group_rules(cluster, spid, rules):
    path = "/ws.v1/security-profile/%s" % spid

    # Allow all dhcp responses in
    rules['logical_port_egress_rules'].append(
        {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
         'port_range_min': constants.DHCP_RESPONSE_PORT,
         'port_range_max': constants.DHCP_RESPONSE_PORT,
         'ip_prefix': '0.0.0.0/0'})
    # If there are no ingress rules add bunk rule to drop all ingress traffic
    if not rules['logical_port_ingress_rules']:
        rules['logical_port_ingress_rules'].append(
            {'ethertype': 'IPv4', 'ip_prefix': '127.0.0.1/32'})
    try:
        body = mk_body(
            logical_port_ingress_rules=rules['logical_port_ingress_rules'],
            logical_port_egress_rules=rules['logical_port_egress_rules'])
        rsp = nsxlib.do_request(HTTP_PUT, path, body, cluster=cluster)
    except exceptions.NotFound as e:
        LOG.error(nsxlib.format_exception("Unknown", e, locals()))
        #FIXME(salvatore-orlando): This should not raise NeutronException
        raise exceptions.NeutronException()
    LOG.debug("Updated Security Profile: %s", rsp)
    return rsp


def update_security_profile(cluster, spid, name):
    return nsxlib.do_request(
        HTTP_PUT,
        nsxlib._build_uri_path(SECPROF_RESOURCE, resource_id=spid),
        jsonutils.dumps({"display_name": utils.check_and_truncate(name)}),
        cluster=cluster)


def delete_security_profile(cluster, spid):
    path = "/ws.v1/security-profile/%s" % spid

    try:
        nsxlib.do_request(HTTP_DELETE, path, cluster=cluster)
    except exceptions.NotFound:
        with excutils.save_and_reraise_exception():
            # This is not necessarily an error condition
            LOG.warn(_LW("Unable to find security profile %s on NSX backend"),
                     spid)
