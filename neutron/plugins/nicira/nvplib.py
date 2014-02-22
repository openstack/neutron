# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc.
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
#
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.


import json

#FIXME(danwent): I'd like this file to get to the point where it has
# no neutron-specific logic in it
from neutron.common import constants
from neutron.common import exceptions as exception
from neutron.openstack.common import log
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.common import utils
from neutron.plugins.nicira import NvpApiClient
from neutron.version import version_info


LOG = log.getLogger(__name__)
# HTTP METHODS CONSTANTS
HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"
# Prefix to be used for all NVP API calls
URI_PREFIX = "/ws.v1"

LSWITCH_RESOURCE = "lswitch"
LSWITCHPORT_RESOURCE = "lport/%s" % LSWITCH_RESOURCE

# Current neutron version
NEUTRON_VERSION = version_info.release_string()

# Maximum page size for a single request
# NOTE(salv-orlando): This might become a version-dependent map should the
# limit be raised in future versions
MAX_PAGE_SIZE = 5000


def _build_uri_path(resource,
                    resource_id=None,
                    parent_resource_id=None,
                    fields=None,
                    relations=None,
                    filters=None,
                    types=None,
                    is_attachment=False,
                    extra_action=None):
    resources = resource.split('/')
    res_path = resources[0] + (resource_id and "/%s" % resource_id or '')
    if len(resources) > 1:
        # There is also a parent resource to account for in the uri
        res_path = "%s/%s/%s" % (resources[1],
                                 parent_resource_id,
                                 res_path)
    if is_attachment:
        res_path = "%s/attachment" % res_path
    elif extra_action:
        res_path = "%s/%s" % (res_path, extra_action)
    params = []
    params.append(fields and "fields=%s" % fields)
    params.append(relations and "relations=%s" % relations)
    params.append(types and "types=%s" % types)
    if filters:
        params.extend(['%s=%s' % (k, v) for (k, v) in filters.iteritems()])
    uri_path = "%s/%s" % (URI_PREFIX, res_path)
    non_empty_params = [x for x in params if x is not None]
    if non_empty_params:
        query_string = '&'.join(non_empty_params)
        if query_string:
            uri_path += "?%s" % query_string
    return uri_path


def get_cluster_version(cluster):
    """Return major/minor version #."""
    # Get control-cluster nodes
    uri = "/ws.v1/control-cluster/node?_page_length=1&fields=uuid"
    res = do_request(HTTP_GET, uri, cluster=cluster)
    if res["result_count"] == 0:
        return None
    node_uuid = res["results"][0]["uuid"]
    # Get control-cluster node status.  It's unsupported to have controllers
    # running different version so we just need the first node version.
    uri = "/ws.v1/control-cluster/node/%s/status" % node_uuid
    res = do_request(HTTP_GET, uri, cluster=cluster)
    version_parts = res["version"].split(".")
    version = "%s.%s" % tuple(version_parts[:2])
    LOG.info(_("NVP controller cluster version: %s"), version)
    return version


def get_single_query_page(path, cluster, page_cursor=None,
                          page_length=1000, neutron_only=True):
    params = []
    if page_cursor:
        params.append("_page_cursor=%s" % page_cursor)
    params.append("_page_length=%s" % page_length)
    # NOTE(salv-orlando): On the NVP backend the 'Quantum' tag is still
    # used for marking Neutron entities in order to preserve compatibility
    if neutron_only:
        params.append("tag_scope=quantum")
    query_params = "&".join(params)
    path = "%s%s%s" % (path, "&" if (path.find("?") != -1) else "?",
                       query_params)
    body = do_request(HTTP_GET, path, cluster=cluster)
    # Result_count won't be returned if _page_cursor is supplied
    return body['results'], body.get('page_cursor'), body.get('result_count')


def get_all_query_pages(path, c):
    need_more_results = True
    result_list = []
    page_cursor = None
    while need_more_results:
        results, page_cursor = get_single_query_page(
            path, c, page_cursor)[:2]
        if not page_cursor:
            need_more_results = False
        result_list.extend(results)
    return result_list


def _plug_interface(cluster, lswitch_id, lport_id, att_obj):
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, lport_id, lswitch_id,
                          is_attachment=True)
    return do_request(HTTP_PUT, uri, json.dumps(att_obj),
                      cluster=cluster)


#------------------------------------------------------------------------------
# Security Profile convenience functions.
#------------------------------------------------------------------------------
EXT_SECURITY_PROFILE_ID_SCOPE = 'nova_spid'
TENANT_ID_SCOPE = 'os_tid'


def format_exception(etype, e, exception_locals):
    """Consistent formatting for exceptions.

    :param etype: a string describing the exception type.
    :param e: the exception.
    :param execption_locals: calling context local variable dict.
    :returns: a formatted string.
    """
    msg = [_("Error. %(type)s exception: %(exc)s.") %
           {'type': etype, 'exc': e}]
    l = dict((k, v) for k, v in exception_locals.iteritems()
             if k != 'request')
    msg.append(_("locals=[%s]") % str(l))
    return ' '.join(msg)


def do_request(*args, **kwargs):
    """Issue a request to the cluster specified in kwargs.

    :param args: a list of positional arguments.
    :param kwargs: a list of keyworkds arguments.
    :returns: the result of the operation loaded into a python
        object or None.
    """
    cluster = kwargs["cluster"]
    try:
        res = cluster.api_client.request(*args)
        if res:
            return json.loads(res)
    except NvpApiClient.ResourceNotFound:
        raise exception.NotFound()
    except NvpApiClient.ReadOnlyMode:
        raise nvp_exc.MaintenanceInProgress()


def mk_body(**kwargs):
    """Convenience function creates and dumps dictionary to string.

    :param kwargs: the key/value pirs to be dumped into a json string.
    :returns: a json string.
    """
    return json.dumps(kwargs, ensure_ascii=False)


# -----------------------------------------------------------------------------
# Security Group API Calls
# -----------------------------------------------------------------------------
def create_security_profile(cluster, tenant_id, security_profile):
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
    tags = [dict(scope='os_tid', tag=tenant_id),
            dict(scope='quantum', tag=NEUTRON_VERSION)]
    display_name = utils.check_and_truncate(security_profile.get('name'))
    body = mk_body(
        tags=tags, display_name=display_name,
        logical_port_ingress_rules=(
            hidden_rules['logical_port_ingress_rules']),
        logical_port_egress_rules=hidden_rules['logical_port_egress_rules']
    )
    rsp = do_request(HTTP_POST, path, body, cluster=cluster)
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
    LOG.debug(_("Created Security Profile: %s"), rsp)
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
        rsp = do_request(HTTP_PUT, path, body, cluster=cluster)
    except exception.NotFound as e:
        LOG.error(format_exception("Unknown", e, locals()))
        #FIXME(salvatore-orlando): This should not raise NeutronException
        raise exception.NeutronException()
    LOG.debug(_("Updated Security Profile: %s"), rsp)
    return rsp


def delete_security_profile(cluster, spid):
    path = "/ws.v1/security-profile/%s" % spid
    try:
        do_request(HTTP_DELETE, path, cluster=cluster)
    except exception.NotFound:
        # This is not necessarily an error condition
        LOG.warn(_("Unable to find security profile %s on NSX backend"),
                 spid)
        raise
