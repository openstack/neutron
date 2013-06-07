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


from copy import copy
import hashlib
import inspect
import json
import logging

from oslo.config import cfg

#FIXME(danwent): I'd like this file to get to the point where it has
# no quantum-specific logic in it
from quantum.common import constants
from quantum.common import exceptions as exception
from quantum.plugins.nicira.nicira_nvp_plugin.common import (
    exceptions as nvp_exc)
from quantum.plugins.nicira.nicira_nvp_plugin import NvpApiClient


# HTTP METHODS CONSTANTS
HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"
# Prefix to be used for all NVP API calls
URI_PREFIX = "/ws.v1"
# Resources exposed by NVP API
LSWITCH_RESOURCE = "lswitch"
LSWITCHPORT_RESOURCE = "lport/%s" % LSWITCH_RESOURCE
LROUTER_RESOURCE = "lrouter"
# Current quantum version
LROUTERPORT_RESOURCE = "lport/%s" % LROUTER_RESOURCE
LROUTERNAT_RESOURCE = "nat/lrouter"
LQUEUE_RESOURCE = "lqueue"
GWSERVICE_RESOURCE = "gateway-service"
QUANTUM_VERSION = "2013.1"
# Other constants for NVP resource
MAX_DISPLAY_NAME_LEN = 40
# Constants for NAT rules
MATCH_KEYS = ["destination_ip_addresses", "destination_port_max",
              "destination_port_min", "source_ip_addresses",
              "source_port_max", "source_port_min", "protocol"]

SNAT_KEYS = ["to_src_port_min", "to_src_port_max", "to_src_ip_min",
             "to_src_ip_max"]

DNAT_KEYS = ["to_dst_port", "to_dst_ip_min", "to_dst_ip_max"]


LOCAL_LOGGING = False
if LOCAL_LOGGING:
    from logging.handlers import SysLogHandler
    FORMAT = ("|%(levelname)s|%(filename)s|%(funcName)s|%(lineno)s"
              "|%(message)s")
    LOG = logging.getLogger(__name__)
    formatter = logging.Formatter(FORMAT)
    syslog = SysLogHandler(address="/dev/log")
    syslog.setFormatter(formatter)
    LOG.addHandler(syslog)
    LOG.setLevel(logging.DEBUG)
else:
    LOG = logging.getLogger(__name__)
    LOG.setLevel(logging.DEBUG)

# TODO(bgh): it would be more efficient to use a bitmap
taken_context_ids = []

_net_type_cache = {}  # cache of {net_id: network_type}
# XXX Only cache default for now
_lqueue_cache = {}


def version_dependent(func):
    func_name = func.__name__

    def dispatch_version_dependent_function(cluster, *args, **kwargs):
        nvp_ver = cluster.api_client.get_nvp_version()
        if nvp_ver:
            ver_major = int(nvp_ver.split('.')[0])
            real_func = NVPLIB_FUNC_DICT[func_name][ver_major]
        func_kwargs = kwargs
        arg_spec = inspect.getargspec(real_func)
        if not arg_spec.keywords and not arg_spec.varargs:
            # drop args unknown to function from func_args
            arg_set = set(func_kwargs.keys())
            for arg in arg_set - set(arg_spec.args):
                del func_kwargs[arg]
        # NOTE(salvatore-orlando): shall we fail here if a required
        # argument is not passed, or let the called function raise?
        real_func(cluster, *args, **func_kwargs)

    return dispatch_version_dependent_function


def _build_uri_path(resource,
                    resource_id=None,
                    parent_resource_id=None,
                    fields=None,
                    relations=None,
                    filters=None,
                    types=None,
                    is_attachment=False):
    resources = resource.split('/')
    res_path = resources[0] + (resource_id and "/%s" % resource_id or '')
    if len(resources) > 1:
        # There is also a parent resource to account for in the uri
        res_path = "%s/%s/%s" % (resources[1],
                                 parent_resource_id,
                                 res_path)
    if is_attachment:
        res_path = "%s/attachment" % res_path
    params = []
    params.append(fields and "fields=%s" % fields)
    params.append(relations and "relations=%s" % relations)
    params.append(types and "types=%s" % types)
    if filters:
        params.extend(['%s=%s' % (k, v) for (k, v) in filters.iteritems()])
    uri_path = "%s/%s" % (URI_PREFIX, res_path)
    non_empty_params = [x for x in params if x is not None]
    if len(non_empty_params):
        query_string = '&'.join(non_empty_params)
        if query_string:
            uri_path += "?%s" % query_string
    return uri_path


def _check_and_truncate_name(display_name):
    if display_name and len(display_name) > MAX_DISPLAY_NAME_LEN:
        LOG.debug(_("Specified name:'%s' exceeds maximum length. "
                    "It will be truncated on NVP"), display_name)
        return display_name[:MAX_DISPLAY_NAME_LEN]
    return display_name


def get_cluster_version(cluster):
    """Return major/minor version #"""
    # Get control-cluster nodes
    uri = "/ws.v1/control-cluster/node?_page_length=1&fields=uuid"
    try:
        res = do_single_request(HTTP_GET, uri, cluster=cluster)
        res = json.loads(res)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if res["result_count"] == 0:
        return None
    node_uuid = res["results"][0]["uuid"]
    # Get control-cluster node status.  It's unsupported to have controllers
    # running different version so we just need the first node version.
    uri = "/ws.v1/control-cluster/node/%s/status" % node_uuid
    try:
        res = do_single_request(HTTP_GET, uri, cluster=cluster)
        res = json.loads(res)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    version_parts = res["version"].split(".")
    version = "%s.%s" % tuple(version_parts[:2])
    LOG.info(_("NVP controller cluster version: %s"), version)
    return version


def get_all_query_pages(path, c):
    need_more_results = True
    result_list = []
    page_cursor = None
    query_marker = "&" if (path.find("?") != -1) else "?"
    while need_more_results:
        page_cursor_str = (
            "_page_cursor=%s" % page_cursor if page_cursor else "")
        res = do_single_request(HTTP_GET, "%s%s%s" %
                                (path, query_marker, page_cursor_str),
                                cluster=c)
        body = json.loads(res)
        page_cursor = body.get('page_cursor')
        if not page_cursor:
            need_more_results = False
        result_list.extend(body['results'])
    return result_list


def do_single_request(*args, **kwargs):
    """Issue a request to a specified cluster if specified via kwargs
       (cluster=<cluster>)."""
    cluster = kwargs["cluster"]
    try:
        req = cluster.api_client.request(*args)
    except NvpApiClient.ResourceNotFound:
        raise exception.NotFound()
    return req


def do_multi_request(*args, **kwargs):
    """Issue a request to all clusters"""
    results = []
    clusters = kwargs["clusters"]
    for x in clusters:
        LOG.debug(_("Issuing request to cluster: %s"), x.name)
        rv = x.api_client.request(*args)
        results.append(rv)
    return results


# -------------------------------------------------------------------
# Network functions
# -------------------------------------------------------------------
def find_port_and_cluster(clusters, port_id):
    """Return (url, cluster_id) of port or (None, None) if port does not exist.
    """
    for c in clusters:
        query = "/ws.v1/lswitch/*/lport?uuid=%s&fields=*" % port_id
        LOG.debug(_("Looking for lswitch with port id "
                    "'%(port_id)s' on: %(c)s"), locals())
        try:
            res = do_single_request(HTTP_GET, query, cluster=c)
        except Exception as e:
            LOG.error(_("get_port_cluster_and_url, exception: %s"), str(e))
            continue
        res = json.loads(res)
        if len(res["results"]) == 1:
            return (res["results"][0], c)
    return (None, None)


def find_lswitch_by_portid(clusters, port_id):
    port, cluster = find_port_and_cluster(clusters, port_id)
    if port and cluster:
        href = port["_href"].split('/')
        return (href[3], cluster)
    return (None, None)


def get_lswitches(cluster, quantum_net_id):
    lswitch_uri_path = _build_uri_path(LSWITCH_RESOURCE, quantum_net_id,
                                       relations="LogicalSwitchStatus")
    results = []
    try:
        resp_obj = do_single_request(HTTP_GET,
                                     lswitch_uri_path,
                                     cluster=cluster)
        ls = json.loads(resp_obj)
        results.append(ls)
        for tag in ls['tags']:
            if (tag['scope'] == "multi_lswitch" and
                tag['tag'] == "True"):
                # Fetch extra logical switches
                extra_lswitch_uri_path = _build_uri_path(
                    LSWITCH_RESOURCE,
                    fields="uuid,display_name,tags,lport_count",
                    relations="LogicalSwitchStatus",
                    filters={'tag': quantum_net_id,
                             'tag_scope': 'quantum_net_id'})
                extra_switches = get_all_query_pages(extra_lswitch_uri_path,
                                                     cluster)
                results.extend(extra_switches)
        return results
    except NvpApiClient.ResourceNotFound:
        raise exception.NetworkNotFound(net_id=quantum_net_id)
    except NvpApiClient.NvpApiException:
        # TODO(salvatore-olrando): Do a better exception handling
        # and re-raising
        LOG.exception(_("An error occured while fetching logical switches "
                        "for Quantum network %s"), quantum_net_id)
        raise exception.QuantumException()


def create_lswitch(cluster, tenant_id, display_name,
                   transport_type=None,
                   transport_zone_uuid=None,
                   vlan_id=None,
                   quantum_net_id=None,
                   shared=None,
                   **kwargs):
    nvp_binding_type = transport_type
    if transport_type in ('flat', 'vlan'):
        nvp_binding_type = 'bridge'
    transport_zone_config = (
        {"zone_uuid": (transport_zone_uuid or
                       cluster.default_tz_uuid),
         "transport_type": (nvp_binding_type or
                            cfg.CONF.NVP.default_transport_type)})
    lswitch_obj = {"display_name": _check_and_truncate_name(display_name),
                   "transport_zones": [transport_zone_config],
                   "tags": [{"tag": tenant_id, "scope": "os_tid"}]}
    if nvp_binding_type == 'bridge' and vlan_id:
        transport_zone_config["binding_config"] = {"vlan_translation":
                                                   [{"transport": vlan_id}]}
    if quantum_net_id:
        lswitch_obj["tags"].append({"tag": quantum_net_id,
                                    "scope": "quantum_net_id"})
    if shared:
        lswitch_obj["tags"].append({"tag": "true",
                                    "scope": "shared"})
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    uri = _build_uri_path(LSWITCH_RESOURCE)
    try:
        lswitch_res = do_single_request(HTTP_POST, uri,
                                        json.dumps(lswitch_obj),
                                        cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    lswitch = json.loads(lswitch_res)
    LOG.debug(_("Created logical switch: %s"), lswitch['uuid'])
    return lswitch


def update_lswitch(cluster, lswitch_id, display_name,
                   tenant_id=None, **kwargs):
    uri = _build_uri_path(LSWITCH_RESOURCE, resource_id=lswitch_id)
    lswitch_obj = {"display_name": _check_and_truncate_name(display_name),
                   "tags": [{"tag": tenant_id, "scope": "os_tid"}]}
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    try:
        resp_obj = do_single_request(HTTP_PUT, uri, json.dumps(lswitch_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Network not found, Error: %s"), str(e))
        raise exception.NetworkNotFound(net_id=lswitch_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    return obj


def create_l2_gw_service(cluster, tenant_id, display_name, devices):
    """ Create a NVP Layer-2 Network Gateway Service.

        :param cluster: The target NVP cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the gateway service.
        :param display_name: Descriptive name of this gateway service
        :param devices: List of transport node uuids (and network
        interfaces on them) to use for the network gateway service
        :raise NvpApiException: if there is a problem while communicating
        with the NVP controller
    """
    tags = [{"tag": tenant_id, "scope": "os_tid"}]
    # NOTE(salvatore-orlando): This is a little confusing, but device_id in
    # NVP is actually the identifier a physical interface on the gateway
    # device, which in the Quantum API is referred as interface_name
    gateways = [{"transport_node_uuid": device['id'],
                 "device_id": device['interface_name'],
                 "type": "L2Gateway"} for device in devices]
    gwservice_obj = {
        "display_name": _check_and_truncate_name(display_name),
        "tags": tags,
        "gateways": gateways,
        "type": "L2GatewayServiceConfig"
    }
    try:
        return json.loads(do_single_request(
            "POST", _build_uri_path(GWSERVICE_RESOURCE),
            json.dumps(gwservice_obj), cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def create_lrouter(cluster, tenant_id, display_name, nexthop):
    """ Create a NVP logical router on the specified cluster.

        :param cluster: The target NVP cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the logical router is being created
        :param display_name: Descriptive name of this logical router
        :param nexthop: External gateway IP address for the logical router
        :raise NvpApiException: if there is a problem while communicating
        with the NVP controller
    """
    tags = [{"tag": tenant_id, "scope": "os_tid"}]
    display_name = _check_and_truncate_name(display_name)
    lrouter_obj = {
        "display_name": display_name,
        "tags": tags,
        "routing_config": {
            "default_route_next_hop": {
                "gateway_ip_address": nexthop,
                "type": "RouterNextHop"
            },
            "type": "SingleDefaultRouteImplicitRoutingConfig"
        },
        "type": "LogicalRouterConfig"
    }
    try:
        return json.loads(do_single_request(HTTP_POST,
                                            _build_uri_path(LROUTER_RESOURCE),
                                            json.dumps(lrouter_obj),
                                            cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def delete_lrouter(cluster, lrouter_id):
    try:
        do_single_request(HTTP_DELETE,
                          _build_uri_path(LROUTER_RESOURCE,
                                          resource_id=lrouter_id),
                          cluster=cluster)
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def delete_l2_gw_service(cluster, gateway_id):
    try:
        do_single_request("DELETE",
                          _build_uri_path(GWSERVICE_RESOURCE,
                                          resource_id=gateway_id),
                          cluster=cluster)
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def get_lrouter(cluster, lrouter_id):
    try:
        return json.loads(do_single_request(HTTP_GET,
                          _build_uri_path(LROUTER_RESOURCE,
                                          resource_id=lrouter_id,
                                          relations='LogicalRouterStatus'),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def get_l2_gw_service(cluster, gateway_id):
    try:
        return json.loads(do_single_request("GET",
                          _build_uri_path(GWSERVICE_RESOURCE,
                                          resource_id=gateway_id),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def get_lrouters(cluster, tenant_id, fields=None, filters=None):
    actual_filters = {}
    if filters:
        actual_filters.update(filters)
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    lrouter_fields = "uuid,display_name,fabric_status,tags"
    return get_all_query_pages(
        _build_uri_path(LROUTER_RESOURCE,
                        fields=lrouter_fields,
                        relations='LogicalRouterStatus',
                        filters=actual_filters),
        cluster)


def get_l2_gw_services(cluster, tenant_id=None,
                       fields=None, filters=None):
    actual_filters = dict(filters or {})
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    return get_all_query_pages(
        _build_uri_path(GWSERVICE_RESOURCE,
                        filters=actual_filters),
        cluster)


def update_l2_gw_service(cluster, gateway_id, display_name):
    # TODO(salvatore-orlando): Allow updates for gateways too
    gwservice_obj = get_l2_gw_service(cluster, gateway_id)
    if not display_name:
        # Nothing to update
        return gwservice_obj
    gwservice_obj["display_name"] = _check_and_truncate_name(display_name)
    try:
        return json.loads(do_single_request("PUT",
                          _build_uri_path(GWSERVICE_RESOURCE,
                                          resource_id=gateway_id),
                          json.dumps(gwservice_obj),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def update_lrouter(cluster, lrouter_id, display_name, nexthop):
    lrouter_obj = get_lrouter(cluster, lrouter_id)
    if not display_name and not nexthop:
        # Nothing to update
        return lrouter_obj
    # It seems that this is faster than the doing an if on display_name
    lrouter_obj["display_name"] = (_check_and_truncate_name(display_name) or
                                   lrouter_obj["display_name"])
    if nexthop:
        nh_element = lrouter_obj["routing_config"].get(
            "default_route_next_hop")
        if nh_element:
            nh_element["gateway_ip_address"] = nexthop
    try:
        return json.loads(do_single_request(HTTP_PUT,
                          _build_uri_path(LROUTER_RESOURCE,
                                          resource_id=lrouter_id),
                          json.dumps(lrouter_obj),
                          cluster=cluster))
    except NvpApiClient.NvpApiException:
        # just log and re-raise - let the caller handle it
        LOG.exception(_("An exception occured while communicating with "
                        "the NVP controller for cluster:%s"), cluster.name)
        raise


def get_all_networks(cluster, tenant_id, networks):
    """Append the quantum network uuids we can find in the given cluster to
       "networks"
       """
    uri = "/ws.v1/lswitch?fields=*&tag=%s&tag_scope=os_tid" % tenant_id
    try:
        resp_obj = do_single_request(HTTP_GET, uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    networks_result = copy(networks)
    return networks_result


def query_networks(cluster, tenant_id, fields="*", tags=None):
    uri = "/ws.v1/lswitch?fields=%s" % fields
    if tags:
        for t in tags:
            uri += "&tag=%s&tag_scope=%s" % (t[0], t[1])
    try:
        resp_obj = do_single_request(HTTP_GET, uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    lswitches = json.loads(resp_obj)["results"]
    nets = [{'net-id': lswitch["uuid"], 'net-name': lswitch["display_name"]}
            for lswitch in lswitches]
    return nets


def delete_network(cluster, net_id, lswitch_id):
    delete_networks(cluster, net_id, [lswitch_id])


def delete_networks(cluster, net_id, lswitch_ids):
    if net_id in _net_type_cache:
        del _net_type_cache[net_id]
    for ls_id in lswitch_ids:
        path = "/ws.v1/lswitch/%s" % ls_id

        try:
            do_single_request(HTTP_DELETE, path, cluster=cluster)
        except NvpApiClient.ResourceNotFound as e:
            LOG.error(_("Network not found, Error: %s"), str(e))
            raise exception.NetworkNotFound(net_id=ls_id)
        except NvpApiClient.NvpApiException as e:
            raise exception.QuantumException()


def query_lswitch_lports(cluster, ls_uuid, fields="*",
                         filters=None, relations=None):
    # Fix filter for attachments
    if filters and "attachment" in filters:
        filters['attachment_vif_uuid'] = filters["attachment"]
        del filters['attachment']
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, parent_resource_id=ls_uuid,
                          fields=fields, filters=filters, relations=relations)
    try:
        resp_obj = do_single_request(HTTP_GET, uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception(_("Logical switch: %s not found"), ls_uuid)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception(_("An error occurred while querying logical ports on "
                        "the NVP platform"))
        raise
    return json.loads(resp_obj)["results"]


def query_lrouter_lports(cluster, lr_uuid, fields="*",
                         filters=None, relations=None):
    uri = _build_uri_path(LROUTERPORT_RESOURCE, parent_resource_id=lr_uuid,
                          fields=fields, filters=filters, relations=relations)
    try:
        resp_obj = do_single_request(HTTP_GET, uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception(_("Logical router: %s not found"), lr_uuid)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception(_("An error occured while querying logical router "
                        "ports on the NVP platfom"))
        raise
    return json.loads(resp_obj)["results"]


def delete_port(cluster, switch, port):
    uri = "/ws.v1/lswitch/" + switch + "/lport/" + port
    try:
        do_single_request(HTTP_DELETE, uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Port or Network not found, Error: %s"), str(e))
        raise exception.PortNotFound(port_id=port['uuid'])
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()


def get_port_by_display_name(clusters, lswitch, display_name):
    """Return (url, cluster_id) of port or raises ResourceNotFound
    """
    query = ("/ws.v1/lswitch/%s/lport?display_name=%s&fields=*" %
             (lswitch, display_name))
    LOG.debug(_("Looking for port with display_name "
                "'%(display_name)s' on: %(lswitch)s"), locals())
    for c in clusters:
        try:
            res_obj = do_single_request(HTTP_GET, query, cluster=c)
        except Exception as e:
            continue
        res = json.loads(res_obj)
        if len(res["results"]) == 1:
            return (res["results"][0], c)

    LOG.error(_("Port or Network not found, Error: %s"), str(e))
    raise exception.PortNotFound(port_id=display_name, net_id=lswitch)


def get_port_by_quantum_tag(cluster, lswitch_uuid, quantum_port_id):
    """Return the NVP UUID of the logical port with tag q_port_id
    equal to quantum_port_id or None if the port is not Found.
    """
    uri = _build_uri_path(LSWITCHPORT_RESOURCE,
                          parent_resource_id=lswitch_uuid,
                          fields='uuid',
                          filters={'tag': quantum_port_id,
                                   'tag_scope': 'q_port_id'})
    LOG.debug(_("Looking for port with q_port_id tag '%(quantum_port_id)s' "
                "on: '%(lswitch_uuid)s'") %
              {'quantum_port_id': quantum_port_id,
               'lswitch_uuid': lswitch_uuid})
    try:
        res_obj = do_single_request(HTTP_GET, uri, cluster=cluster)
    except Exception:
        LOG.exception(_("An exception occurred while querying NVP ports"))
        raise
    res = json.loads(res_obj)
    num_results = len(res["results"])
    if num_results >= 1:
        if num_results > 1:
            LOG.warn(_("Found '%(num_ports)d' ports with "
                       "q_port_id tag: '%(quantum_port_id)s'. "
                       "Only 1 was expected.") %
                     {'num_ports': num_results,
                      'quantum_port_id': quantum_port_id})
        return res["results"][0]


def get_port(cluster, network, port, relations=None):
    LOG.info(_("get_port() %(network)s %(port)s"), locals())
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "?"
    if relations:
        uri += "relations=%s" % relations
    try:
        resp_obj = do_single_request(HTTP_GET, uri, cluster=cluster)
        port = json.loads(resp_obj)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Port or Network not found, Error: %s"), str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return port


def _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles, queue_id):
    lport_obj['allowed_address_pairs'] = []
    if port_security_enabled:
        for fixed_ip in fixed_ips:
            ip_address = fixed_ip.get('ip_address')
            if ip_address:
                lport_obj['allowed_address_pairs'].append(
                    {'mac_address': mac_address, 'ip_address': ip_address})
        # add address pair allowing src_ip 0.0.0.0 to leave
        # this is required for outgoing dhcp request
        lport_obj["allowed_address_pairs"].append(
            {"mac_address": mac_address,
             "ip_address": "0.0.0.0"})
    lport_obj['security_profiles'] = list(security_profiles or [])
    lport_obj['queue_uuid'] = queue_id


def update_port(cluster, lswitch_uuid, lport_uuid, quantum_port_id, tenant_id,
                display_name, device_id, admin_status_enabled,
                mac_address=None, fixed_ips=None, port_security_enabled=None,
                security_profiles=None, queue_id=None):
    # device_id can be longer than 40 so we rehash it
    hashed_device_id = hashlib.sha1(device_id).hexdigest()
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=_check_and_truncate_name(display_name),
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=quantum_port_id),
              dict(scope='vm_id', tag=hashed_device_id)])
    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id)

    path = "/ws.v1/lswitch/" + lswitch_uuid + "/lport/" + lport_uuid
    try:
        resp_obj = do_single_request(HTTP_PUT, path, json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Port or Network not found, Error: %s"), str(e))
        raise exception.PortNotFound(port_id=lport_uuid, net_id=lswitch_uuid)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    result = json.loads(resp_obj)
    LOG.debug(_("Updated logical port %(result)s on logical swtich %(uuid)s"),
              {'result': result['uuid'], 'uuid': lswitch_uuid})
    return result


def create_lport(cluster, lswitch_uuid, tenant_id, quantum_port_id,
                 display_name, device_id, admin_status_enabled,
                 mac_address=None, fixed_ips=None, port_security_enabled=None,
                 security_profiles=None, queue_id=None):
    """ Creates a logical port on the assigned logical switch """
    # device_id can be longer than 40 so we rehash it
    hashed_device_id = hashlib.sha1(device_id).hexdigest()
    display_name = _check_and_truncate_name(display_name)
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=quantum_port_id),
              dict(scope='vm_id', tag=hashed_device_id)],
    )

    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id)

    path = _build_uri_path(LSWITCHPORT_RESOURCE,
                           parent_resource_id=lswitch_uuid)
    try:
        resp_obj = do_single_request(HTTP_POST, path,
                                     json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Logical switch not found, Error: %s"), str(e))
        raise

    result = json.loads(resp_obj)
    LOG.debug(_("Created logical port %(result)s on logical swtich %(uuid)s"),
              {'result': result['uuid'], 'uuid': lswitch_uuid})
    return result


def create_router_lport(cluster, lrouter_uuid, tenant_id, quantum_port_id,
                        display_name, admin_status_enabled, ip_addresses):
    """ Creates a logical port on the assigned logical router """
    tags = [dict(scope='os_tid', tag=tenant_id),
            dict(scope='q_port_id', tag=quantum_port_id)]
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=tags,
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    path = _build_uri_path(LROUTERPORT_RESOURCE,
                           parent_resource_id=lrouter_uuid)
    try:
        resp_obj = do_single_request(HTTP_POST, path,
                                     json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Logical router not found, Error: %s"), str(e))
        raise

    result = json.loads(resp_obj)
    LOG.debug(_("Created logical port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': result['uuid'],
               'lrouter_uuid': lrouter_uuid})
    return result


def update_router_lport(cluster, lrouter_uuid, lrouter_port_uuid,
                        tenant_id, quantum_port_id, display_name,
                        admin_status_enabled, ip_addresses):
    """ Updates a logical port on the assigned logical router """
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=quantum_port_id)],
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    # Do not pass null items to NVP
    for key in lport_obj.keys():
        if lport_obj[key] is None:
            del lport_obj[key]
    path = _build_uri_path(LROUTERPORT_RESOURCE,
                           lrouter_port_uuid,
                           parent_resource_id=lrouter_uuid)
    try:
        resp_obj = do_single_request(HTTP_PUT, path,
                                     json.dumps(lport_obj),
                                     cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Logical router or router port not found, "
                    "Error: %s"), str(e))
        raise

    result = json.loads(resp_obj)
    LOG.debug(_("Updated logical port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': lrouter_port_uuid, 'lrouter_uuid': lrouter_uuid})
    return result


def delete_router_lport(cluster, lrouter_uuid, lport_uuid):
    """ Creates a logical port on the assigned logical router """
    path = _build_uri_path(LROUTERPORT_RESOURCE, lport_uuid, lrouter_uuid)
    try:
        do_single_request(HTTP_DELETE, path, cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Logical router not found, Error: %s"), str(e))
        raise
    LOG.debug(_("Delete logical router port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': lport_uuid,
               'lrouter_uuid': lrouter_uuid})


def delete_peer_router_lport(cluster, lr_uuid, ls_uuid, lp_uuid):
    nvp_port = get_port(cluster, ls_uuid, lp_uuid,
                        relations="LogicalPortAttachment")
    try:
        relations = nvp_port.get('_relations')
        if relations:
            att_data = relations.get('LogicalPortAttachment')
            if att_data:
                lrp_uuid = att_data.get('peer_port_uuid')
                if lrp_uuid:
                    delete_router_lport(cluster, lr_uuid, lrp_uuid)
    except (NvpApiClient.NvpApiException, NvpApiClient.ResourceNotFound):
        LOG.exception(_("Unable to fetch and delete peer logical "
                        "router port for logical switch port:%s"),
                      lp_uuid)
        raise


def find_router_gw_port(context, cluster, router_id):
    """ Retrieves the external gateway port for a NVP logical router """

    # Find the uuid of nvp ext gw logical router port
    # TODO(salvatore-orlando): Consider storing it in Quantum DB
    results = query_lrouter_lports(
        cluster, router_id,
        relations="LogicalPortAttachment")
    for lport in results:
        if '_relations' in lport:
            attachment = lport['_relations'].get('LogicalPortAttachment')
            if attachment and attachment.get('type') == 'L3GatewayAttachment':
                return lport


def plug_router_port_attachment(cluster, router_id, port_id,
                                attachment_uuid, nvp_attachment_type,
                                attachment_vlan=None):
    """Attach a router port to the given attachment.
       Current attachment types:
       - PatchAttachment [-> logical switch port uuid]
       - L3GatewayAttachment [-> L3GatewayService uuid]
       For the latter attachment type a VLAN ID can be specified as well
    """
    uri = _build_uri_path(LROUTERPORT_RESOURCE, port_id, router_id,
                          is_attachment=True)
    attach_obj = {}
    attach_obj["type"] = nvp_attachment_type
    if nvp_attachment_type == "PatchAttachment":
        attach_obj["peer_port_uuid"] = attachment_uuid
    elif nvp_attachment_type == "L3GatewayAttachment":
        attach_obj["l3_gateway_service_uuid"] = attachment_uuid
        if attachment_vlan:
            attach_obj['vlan_id'] = attachment_vlan
    else:
        raise Exception(_("Invalid NVP attachment type '%s'"),
                        nvp_attachment_type)
    try:
        resp_obj = do_single_request(
            HTTP_PUT, uri, json.dumps(attach_obj), cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        LOG.exception(_("Router Port not found, Error: %s"), str(e))
        raise
    except NvpApiClient.Conflict as e:
        LOG.exception(_("Conflict while setting router port attachment"))
        raise
    except NvpApiClient.NvpApiException as e:
        LOG.exception(_("Unable to plug attachment into logical router port"))
        raise
    result = json.loads(resp_obj)
    return result


def get_port_status(cluster, lswitch_id, port_id):
    """Retrieve the operational status of the port"""
    try:
        r = do_single_request(HTTP_GET,
                              "/ws.v1/lswitch/%s/lport/%s/status" %
                              (lswitch_id, port_id), cluster=cluster)
        r = json.loads(r)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error(_("Port not found, Error: %s"), str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=lswitch_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    if r['link_status_up'] is True:
        return constants.PORT_STATUS_ACTIVE
    else:
        return constants.PORT_STATUS_DOWN


def _plug_interface(cluster, lswitch_id, lport_id, att_obj):
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, lport_id, lswitch_id,
                          is_attachment=True)
    try:
        resp_obj = do_single_request(HTTP_PUT, uri, json.dumps(att_obj),
                                     cluster=cluster)
    except NvpApiClient.NvpApiException:
        LOG.exception(_("Exception while plugging an attachment:%(att)s "
                        "into NVP port:%(port)s for NVP logical switch "
                        "%(net)s"), {'net': lswitch_id,
                                     'port': lport_id,
                                     'att': att_obj})
        raise

    result = json.dumps(resp_obj)
    return result


def plug_l2_gw_service(cluster, lswitch_id, lport_id,
                       gateway_id, vlan_id=None):
    """ Plug a Layer-2 Gateway Attachment object in a logical port """
    att_obj = {'type': 'L2GatewayAttachment',
               'l2_gateway_service_uuid': gateway_id}
    if vlan_id:
        att_obj['vlan_id'] = vlan_id
    return _plug_interface(cluster, lswitch_id, lport_id, att_obj)


def plug_interface(cluster, lswitch_id, port, type, attachment=None):
    """ Plug a VIF Attachment object in a logical port """
    lport_obj = {}
    if attachment:
        lport_obj["vif_uuid"] = attachment

    lport_obj["type"] = type
    return _plug_interface(cluster, lswitch_id, port, lport_obj)

#------------------------------------------------------------------------------
# Security Profile convenience functions.
#------------------------------------------------------------------------------
EXT_SECURITY_PROFILE_ID_SCOPE = 'nova_spid'
TENANT_ID_SCOPE = 'os_tid'


def format_exception(etype, e, execption_locals, request=None):
    """Consistent formatting for exceptions.
    :param etype: a string describing the exception type.
    :param e: the exception.
    :param request: the request object.
    :param execption_locals: calling context local variable dict.
    :returns: a formatted string.
    """
    msg = ["Error. %s exception: %s." % (etype, e)]
    if request:
        msg.append("request=[%s]" % request)
        if request.body:
            msg.append("request.body=[%s]" % str(request.body))
    l = dict((k, v) for k, v in execption_locals if k != 'request')
    msg.append("locals=[%s]" % str(l))
    return ' '.join(msg)


def do_request(*args, **kwargs):
    """Convenience function wraps do_single_request.

    :param args: a list of positional arguments.
    :param kwargs: a list of keyworkds arguments.
    :returns: the result of do_single_request loaded into a python object
        or None."""
    res = do_single_request(*args, **kwargs)
    if res:
        return json.loads(res)
    return res


def mk_body(**kwargs):
    """Convenience function creates and dumps dictionary to string.

    :param kwargs: the key/value pirs to be dumped into a json string.
    :returns: a json string."""
    return json.dumps(kwargs, ensure_ascii=False)


def set_tenant_id_tag(tenant_id, taglist=None):
    """Convenience function to add tenant_id tag to taglist.

    :param tenant_id: the tenant_id to set.
    :param taglist: the taglist to append to (or None).
    :returns: a new taglist that includes the old taglist with the new
        tenant_id tag set."""
    new_taglist = []
    if taglist:
        new_taglist = [x for x in taglist if x['scope'] != TENANT_ID_SCOPE]
    new_taglist.append(dict(scope=TENANT_ID_SCOPE, tag=tenant_id))
    return new_taglist


# -----------------------------------------------------------------------------
# Security Group API Calls
# -----------------------------------------------------------------------------
def create_security_profile(cluster, tenant_id, security_profile):
    path = "/ws.v1/security-profile"
    tags = set_tenant_id_tag(tenant_id)
    # Allow all dhcp responses and all ingress traffic
    hidden_rules = {'logical_port_egress_rules':
                    [{'ethertype': 'IPv4',
                      'protocol': constants.UDP_PROTOCOL,
                      'port_range_min': constants.DHCP_RESPONSE_PORT,
                      'port_range_max': constants.DHCP_RESPONSE_PORT,
                      'ip_prefix': '0.0.0.0/0'}],
                    'logical_port_ingress_rules':
                    [{'ethertype': 'IPv4'},
                     {'ethertype': 'IPv6'}]}
    try:
        display_name = _check_and_truncate_name(security_profile.get('name'))
        body = mk_body(
            tags=tags, display_name=display_name,
            logical_port_ingress_rules=(
                hidden_rules['logical_port_ingress_rules']),
            logical_port_egress_rules=hidden_rules['logical_port_egress_rules']
        )
        rsp = do_request(HTTP_POST, path, body, cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.QuantumException()
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
        {'ethertype': 'IPv4', 'protocol': constants.UDP_PROTOCOL,
         'port_range_min': constants.DHCP_RESPONSE_PORT,
         'port_range_max': constants.DHCP_RESPONSE_PORT,
         'ip_prefix': '0.0.0.0/0'})
    # If there are no ingress rules add bunk rule to drop all ingress traffic
    if not len(rules['logical_port_ingress_rules']):
        rules['logical_port_ingress_rules'].append(
            {'ethertype': 'IPv4', 'ip_prefix': '127.0.0.1/32'})
    try:
        body = mk_body(
            logical_port_ingress_rules=rules['logical_port_ingress_rules'],
            logical_port_egress_rules=rules['logical_port_egress_rules'])
        rsp = do_request(HTTP_PUT, path, body, cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.QuantumException()
    LOG.debug(_("Updated Security Profile: %s"), rsp)
    return rsp


def delete_security_profile(cluster, spid):
    path = "/ws.v1/security-profile/%s" % spid

    try:
        do_request(HTTP_DELETE, path, cluster=cluster)
    except NvpApiClient.NvpApiException as e:
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.QuantumException()


def _create_nat_match_obj(**kwargs):
    nat_match_obj = {'ethertype': 'IPv4'}
    delta = set(kwargs.keys()) - set(MATCH_KEYS)
    if delta:
        raise Exception(_("Invalid keys for NAT match: %s"), delta)
    nat_match_obj.update(kwargs)
    return nat_match_obj


def _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj):
    LOG.debug(_("Creating NAT rule: %s"), nat_rule_obj)
    uri = _build_uri_path(LROUTERNAT_RESOURCE, parent_resource_id=router_id)
    try:
        resp = do_single_request(HTTP_POST, uri, json.dumps(nat_rule_obj),
                                 cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception(_("NVP Logical Router %s not found"), router_id)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception(_("An error occurred while creating the NAT rule "
                        "on the NVP platform"))
        raise
    rule = json.loads(resp)
    return rule


def _build_snat_rule_obj(min_src_ip, max_src_ip, nat_match_obj):
    return {"to_source_ip_address_min": min_src_ip,
            "to_source_ip_address_max": max_src_ip,
            "type": "SourceNatRule",
            "match": nat_match_obj}


def create_lrouter_nosnat_rule_v2(cluster, _router_id, _match_criteria=None):
    LOG.info(_("No SNAT rules cannot be applied as they are not available in "
               "this version of the NVP platform"))


def create_lrouter_snat_rule_v2(cluster, router_id,
                                min_src_ip, max_src_ip, match_criteria=None):

    nat_match_obj = _create_nat_match_obj(**match_criteria)
    nat_rule_obj = _build_snat_rule_obj(min_src_ip, max_src_ip, nat_match_obj)
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


def create_lrouter_dnat_rule_v2(cluster, router_id, dst_ip,
                                to_dst_port=None, match_criteria=None):

    nat_match_obj = _create_nat_match_obj(**match_criteria)
    nat_rule_obj = {
        "to_destination_ip_address_min": dst_ip,
        "to_destination_ip_address_max": dst_ip,
        "type": "DestinationNatRule",
        "match": nat_match_obj
    }
    if to_dst_port:
        nat_rule_obj['to_destination_port'] = to_dst_port
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


def create_lrouter_nosnat_rule_v3(cluster, router_id, order=None,
                                  match_criteria=None):
    nat_match_obj = _create_nat_match_obj(**match_criteria)
    nat_rule_obj = {
        "type": "NoSourceNatRule",
        "match": nat_match_obj
    }
    if order:
        nat_rule_obj['order'] = order
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


def create_lrouter_snat_rule_v3(cluster, router_id, min_src_ip, max_src_ip,
                                order=None, match_criteria=None):
    nat_match_obj = _create_nat_match_obj(**match_criteria)
    nat_rule_obj = _build_snat_rule_obj(min_src_ip, max_src_ip, nat_match_obj)
    if order:
        nat_rule_obj['order'] = order
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


def create_lrouter_dnat_rule_v3(cluster, router_id, dst_ip, to_dst_port=None,
                                order=None, match_criteria=None):

    nat_match_obj = _create_nat_match_obj(**match_criteria)
    nat_rule_obj = {
        "to_destination_ip_address": dst_ip,
        "type": "DestinationNatRule",
        "match": nat_match_obj
    }
    if to_dst_port:
        nat_rule_obj['to_destination_port'] = to_dst_port
    if order:
        nat_rule_obj['order'] = order
    return _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj)


@version_dependent
def create_lrouter_dnat_rule(cluster, *args, **kwargs):
    pass


@version_dependent
def create_lrouter_snat_rule(cluster, *args, **kwargs):
    pass


@version_dependent
def create_lrouter_nosnat_rule(cluster, *args, **kwargs):
    pass


def delete_nat_rules_by_match(cluster, router_id, rule_type,
                              max_num_expected,
                              min_num_expected=0,
                              **kwargs):
    # remove nat rules
    nat_rules = query_nat_rules(cluster, router_id)
    to_delete_ids = []
    for r in nat_rules:
        if (r['type'] != rule_type):
            continue

        for key, value in kwargs.iteritems():
            if not (key in r['match'] and r['match'][key] == value):
                break
        else:
            to_delete_ids.append(r['uuid'])
    if not (len(to_delete_ids) in
            range(min_num_expected, max_num_expected + 1)):
        raise nvp_exc.NvpNatRuleMismatch(actual_rules=len(to_delete_ids),
                                         min_rules=min_num_expected,
                                         max_rules=max_num_expected)

    for rule_id in to_delete_ids:
        delete_router_nat_rule(cluster, router_id, rule_id)


def delete_router_nat_rule(cluster, router_id, rule_id):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, rule_id, router_id)
    try:
        do_single_request(HTTP_DELETE, uri, cluster=cluster)
    except NvpApiClient.NvpApiException:
        LOG.exception(_("An error occurred while removing NAT rule "
                        "'%(nat_rule_uuid)s' for logical "
                        "router '%(lrouter_uuid)s'"),
                      {'nat_rule_uuid': rule_id, 'lrouter_uuid': router_id})
        raise


def get_router_nat_rule(cluster, tenant_id, router_id, rule_id):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, rule_id, router_id)
    try:
        resp = do_single_request(HTTP_GET, uri, cluster=cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception(_("NAT rule %s not found"), rule_id)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception(_("An error occured while retrieving NAT rule '%s'"
                        "from NVP platform"), rule_id)
        raise
    res = json.loads(resp)
    return res


def query_nat_rules(cluster, router_id, fields="*", filters=None):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, parent_resource_id=router_id,
                          fields=fields, filters=filters)
    try:
        result = get_all_query_pages(uri, cluster)
    except NvpApiClient.ResourceNotFound:
        LOG.exception(_("NVP Logical Router '%s' not found"), router_id)
        raise
    except NvpApiClient.NvpApiException:
        LOG.exception(_("An error occured while retrieving NAT rules for "
                        "NVP logical router '%s'"), router_id)
        raise
    return result


# NOTE(salvatore-orlando): The following FIXME applies in general to
# each operation on list attributes.
# FIXME(salvatore-orlando): need a lock around the list of IPs on an iface
def update_lrouter_port_ips(cluster, lrouter_id, lport_id,
                            ips_to_add, ips_to_remove):
    uri = _build_uri_path(LROUTERPORT_RESOURCE, lport_id, lrouter_id)
    try:
        port = json.loads(do_single_request(HTTP_GET, uri, cluster=cluster))
        # TODO(salvatore-orlando): Enforce ips_to_add intersection with
        # ips_to_remove is empty
        ip_address_set = set(port['ip_addresses'])
        ip_address_set = ip_address_set - set(ips_to_remove)
        ip_address_set = ip_address_set | set(ips_to_add)
        # Set is not JSON serializable - convert to list
        port['ip_addresses'] = list(ip_address_set)
        do_single_request(HTTP_PUT, uri, json.dumps(port), cluster=cluster)
    except NvpApiClient.ResourceNotFound as e:
        msg = (_("Router Port %(lport_id)s not found on router "
                 "%(lrouter_id)s") % locals())
        LOG.exception(msg)
        raise nvp_exc.NvpPluginException(err_msg=msg)
    except NvpApiClient.NvpApiException as e:
        msg = _("An exception occurred while updating IP addresses on a "
                "router logical port:%s") % str(e)
        LOG.exception(msg)
        raise nvp_exc.NvpPluginException(err_msg=msg)


# TODO(salvatore-orlando): Also handle changes in minor versions
NVPLIB_FUNC_DICT = {
    'create_lrouter_dnat_rule': {2: create_lrouter_dnat_rule_v2,
                                 3: create_lrouter_dnat_rule_v3},
    'create_lrouter_snat_rule': {2: create_lrouter_snat_rule_v2,
                                 3: create_lrouter_snat_rule_v3},
    'create_lrouter_nosnat_rule': {2: create_lrouter_nosnat_rule_v2,
                                   3: create_lrouter_nosnat_rule_v3}
}


# -----------------------------------------------------------------------------
# QOS API Calls
# -----------------------------------------------------------------------------
def create_lqueue(cluster, lqueue):
    uri = _build_uri_path(LQUEUE_RESOURCE)
    lqueue['tags'] = [{'tag': QUANTUM_VERSION, 'scope': 'quantum'}]
    try:
        resp_obj = do_single_request(HTTP_POST, uri, json.dumps(lqueue),
                                     cluster=cluster)
    except NvpApiClient.NvpApiException:
        LOG.exception(_("Failed to create logical queue"))
        raise exception.QuantumException()
    return json.loads(resp_obj)['uuid']


def delete_lqueue(cluster, id):
    try:
        do_single_request(HTTP_DELETE,
                          _build_uri_path(LQUEUE_RESOURCE,
                                          resource_id=id),
                          cluster=cluster)
    except Exception:
        LOG.exception(_("Failed to delete logical queue"))
        raise exception.QuantumException()


# -----------------------------------------------------------------------------
# NVP API Calls for check_nvp_config utility
# -----------------------------------------------------------------------------
def check_cluster_connectivity(cluster):
    """Make sure that we can issue a request to each of the cluster nodes"""
    try:
        resp = do_single_request(HTTP_GET, "/ws.v1/control-cluster",
                                 cluster=cluster)
    except Exception as e:
        msg = "Failed to connect to cluster %s: %s" % (cluster, str(e))
        raise Exception(msg)
    return json.loads(resp)


def get_gateway_services(cluster):
    try:
        resp = do_single_request(HTTP_GET,
                                 "/ws.v1/gateway-service?fields=uuid",
                                 cluster=cluster)
    except Exception as e:
        msg = "Failed to connect to cluster %s: %s" % (cluster, str(e))
        raise Exception(msg)
    return json.loads(resp)


def get_transport_zones(cluster):
    try:
        resp = do_single_request(HTTP_GET,
                                 "/ws.v1/transport-zone?fields=uuid",
                                 cluster=cluster)
    except Exception as e:
        msg = "Failed to connect to cluster %s: %s" % (cluster, str(e))
        raise Exception(msg)
    return json.loads(resp)
