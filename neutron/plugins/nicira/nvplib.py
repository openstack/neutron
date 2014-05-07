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


import hashlib
import inspect
import json

#FIXME(danwent): I'd like this file to get to the point where it has
# no neutron-specific logic in it
from neutron.common import constants
from neutron.common import exceptions as exception
from neutron.openstack.common import excutils
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
# Resources exposed by NVP API
LSWITCH_RESOURCE = "lswitch"
LSWITCHPORT_RESOURCE = "lport/%s" % LSWITCH_RESOURCE
LROUTER_RESOURCE = "lrouter"
LROUTERPORT_RESOURCE = "lport/%s" % LROUTER_RESOURCE
LROUTERRIB_RESOURCE = "rib/%s" % LROUTER_RESOURCE
LROUTERNAT_RESOURCE = "nat/lrouter"
LQUEUE_RESOURCE = "lqueue"
GWSERVICE_RESOURCE = "gateway-service"
# Current neutron version
NEUTRON_VERSION = version_info.release_string()
# Constants for NAT rules
MATCH_KEYS = ["destination_ip_addresses", "destination_port_max",
              "destination_port_min", "source_ip_addresses",
              "source_port_max", "source_port_min", "protocol"]

SNAT_KEYS = ["to_src_port_min", "to_src_port_max", "to_src_ip_min",
             "to_src_ip_max"]

DNAT_KEYS = ["to_dst_port", "to_dst_ip_min", "to_dst_ip_max"]
# Maximum page size for a single request
# NOTE(salv-orlando): This might become a version-dependent map should the
# limit be raised in future versions
MAX_PAGE_SIZE = 5000

# TODO(bgh): it would be more efficient to use a bitmap
taken_context_ids = []

# XXX Only cache default for now
_lqueue_cache = {}


def device_id_to_vm_id(device_id, obfuscate=False):
    # device_id can be longer than 40 characters, for example
    # a device_id for a dhcp port is like the following:
    #
    # dhcp83b5fdeb-e3b4-5e18-ac5f-55161...80747326-47d7-46c2-a87a-cf6d5194877c
    #
    # To fit it into an NVP tag we need to hash it, however device_id
    # used for ports associated to VM's are small enough so let's skip the
    # hashing
    if len(device_id) > utils.MAX_DISPLAY_NAME_LEN or obfuscate:
        return hashlib.sha1(device_id).hexdigest()
    else:
        return device_id


def version_dependent(wrapped_func):
    func_name = wrapped_func.__name__

    def dispatch_version_dependent_function(cluster, *args, **kwargs):
        # Call the wrapper function, in case we need to
        # run validation checks regarding versions. It
        # should return the NVP version
        v = (wrapped_func(cluster, *args, **kwargs) or
             cluster.api_client.get_nvp_version())
        func = get_function_by_version(func_name, v)
        func_kwargs = kwargs
        arg_spec = inspect.getargspec(func)
        if not arg_spec.keywords and not arg_spec.varargs:
            # drop args unknown to function from func_args
            arg_set = set(func_kwargs.keys())
            for arg in arg_set - set(arg_spec.args):
                del func_kwargs[arg]
        # NOTE(salvatore-orlando): shall we fail here if a required
        # argument is not passed, or let the called function raise?
        return func(cluster, *args, **func_kwargs)

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


# -------------------------------------------------------------------
# Network functions
# -------------------------------------------------------------------
def get_lswitches(cluster, neutron_net_id):
    lswitch_uri_path = _build_uri_path(LSWITCH_RESOURCE, neutron_net_id,
                                       relations="LogicalSwitchStatus")
    results = []
    try:
        ls = do_request(HTTP_GET, lswitch_uri_path, cluster=cluster)
        results.append(ls)
        for tag in ls['tags']:
            if (tag['scope'] == "multi_lswitch" and
                tag['tag'] == "True"):
                # Fetch extra logical switches
                extra_lswitch_uri_path = _build_uri_path(
                    LSWITCH_RESOURCE,
                    fields="uuid,display_name,tags,lport_count",
                    relations="LogicalSwitchStatus",
                    filters={'tag': neutron_net_id,
                             'tag_scope': 'quantum_net_id'})
                extra_switches = get_all_query_pages(extra_lswitch_uri_path,
                                                     cluster)
                results.extend(extra_switches)
        return results
    except exception.NotFound:
        raise exception.NetworkNotFound(net_id=neutron_net_id)


def create_lswitch(cluster, tenant_id, display_name,
                   transport_zones_config,
                   neutron_net_id=None,
                   shared=None,
                   **kwargs):
    lswitch_obj = {"display_name": utils.check_and_truncate(display_name),
                   "transport_zones": transport_zones_config,
                   "tags": [{"tag": tenant_id, "scope": "os_tid"},
                            {"tag": NEUTRON_VERSION, "scope": "quantum"}]}
    if neutron_net_id:
        lswitch_obj["tags"].append({"tag": neutron_net_id,
                                    "scope": "quantum_net_id"})
    if shared:
        lswitch_obj["tags"].append({"tag": "true",
                                    "scope": "shared"})
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    uri = _build_uri_path(LSWITCH_RESOURCE)
    lswitch = do_request(HTTP_POST, uri, json.dumps(lswitch_obj),
                         cluster=cluster)
    LOG.debug(_("Created logical switch: %s"), lswitch['uuid'])
    return lswitch


def update_lswitch(cluster, lswitch_id, display_name,
                   tenant_id=None, **kwargs):
    uri = _build_uri_path(LSWITCH_RESOURCE, resource_id=lswitch_id)
    lswitch_obj = {"display_name": utils.check_and_truncate(display_name),
                   "tags": [{"tag": tenant_id, "scope": "os_tid"},
                            {"tag": NEUTRON_VERSION, "scope": "quantum"}]}
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    try:
        return do_request(HTTP_PUT, uri, json.dumps(lswitch_obj),
                          cluster=cluster)
    except exception.NotFound as e:
        LOG.error(_("Network not found, Error: %s"), str(e))
        raise exception.NetworkNotFound(net_id=lswitch_id)


def create_l2_gw_service(cluster, tenant_id, display_name, devices):
    """Create a NVP Layer-2 Network Gateway Service.

        :param cluster: The target NVP cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the gateway service.
        :param display_name: Descriptive name of this gateway service
        :param devices: List of transport node uuids (and network
        interfaces on them) to use for the network gateway service
        :raise NvpApiException: if there is a problem while communicating
        with the NVP controller
    """
    tags = [{"tag": tenant_id, "scope": "os_tid"},
            {"tag": NEUTRON_VERSION, "scope": "quantum"}]
    # NOTE(salvatore-orlando): This is a little confusing, but device_id in
    # NVP is actually the identifier a physical interface on the gateway
    # device, which in the Neutron API is referred as interface_name
    gateways = [{"transport_node_uuid": device['id'],
                 "device_id": device['interface_name'],
                 "type": "L2Gateway"} for device in devices]
    gwservice_obj = {
        "display_name": utils.check_and_truncate(display_name),
        "tags": tags,
        "gateways": gateways,
        "type": "L2GatewayServiceConfig"
    }
    return do_request(
        "POST", _build_uri_path(GWSERVICE_RESOURCE),
        json.dumps(gwservice_obj), cluster=cluster)


def _prepare_lrouter_body(name, tenant_id, router_type,
                          distributed=None, **kwargs):
    body = {
        "display_name": utils.check_and_truncate(name),
        "tags": [{"tag": tenant_id, "scope": "os_tid"},
                 {"tag": NEUTRON_VERSION, "scope": "quantum"}],
        "routing_config": {
            "type": router_type
        },
        "type": "LogicalRouterConfig"
    }
    # add the distributed key only if not None (ie: True or False)
    if distributed is not None:
        body['distributed'] = distributed
    if kwargs:
        body["routing_config"].update(kwargs)
    return body


def _create_implicit_routing_lrouter(cluster, tenant_id,
                                     display_name, nexthop,
                                     distributed=None):
    implicit_routing_config = {
        "default_route_next_hop": {
            "gateway_ip_address": nexthop,
            "type": "RouterNextHop"
        },
    }
    lrouter_obj = _prepare_lrouter_body(
        display_name, tenant_id,
        "SingleDefaultRouteImplicitRoutingConfig",
        distributed=distributed,
        **implicit_routing_config)
    return do_request(HTTP_POST, _build_uri_path(LROUTER_RESOURCE),
                      json.dumps(lrouter_obj), cluster=cluster)


def create_implicit_routing_lrouter(cluster, tenant_id,
                                    display_name, nexthop):
    """Create a NVP logical router on the specified cluster.

        :param cluster: The target NVP cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the logical router is being created
        :param display_name: Descriptive name of this logical router
        :param nexthop: External gateway IP address for the logical router
        :raise NvpApiException: if there is a problem while communicating
        with the NVP controller
    """
    return _create_implicit_routing_lrouter(
        cluster, tenant_id, display_name, nexthop)


def create_implicit_routing_lrouter_with_distribution(
    cluster, tenant_id, display_name, nexthop, distributed=None):
    """Create a NVP logical router on the specified cluster.

    This function also allows for creating distributed lrouters
    :param cluster: The target NVP cluster
    :param tenant_id: Identifier of the Openstack tenant for which
    the logical router is being created
    :param display_name: Descriptive name of this logical router
    :param nexthop: External gateway IP address for the logical router
    :param distributed: True for distributed logical routers
    :raise NvpApiException: if there is a problem while communicating
    with the NVP controller
    """
    return _create_implicit_routing_lrouter(
        cluster, tenant_id, display_name, nexthop, distributed)


def create_explicit_routing_lrouter(cluster, tenant_id,
                                    display_name, nexthop,
                                    distributed=None):
    lrouter_obj = _prepare_lrouter_body(
        display_name, tenant_id, "RoutingTableRoutingConfig",
        distributed=distributed)
    router = do_request(HTTP_POST, _build_uri_path(LROUTER_RESOURCE),
                        json.dumps(lrouter_obj), cluster=cluster)
    default_gw = {'prefix': '0.0.0.0/0', 'next_hop_ip': nexthop}
    create_explicit_route_lrouter(cluster, router['uuid'], default_gw)
    return router


@version_dependent
def create_lrouter(cluster, *args, **kwargs):
    if kwargs.get('distributed', None):
        v = cluster.api_client.get_nvp_version()
        if (v.major, v.minor) < (3, 1):
            raise nvp_exc.NvpInvalidVersion(version=v)
        return v


def delete_lrouter(cluster, lrouter_id):
    do_request(HTTP_DELETE, _build_uri_path(LROUTER_RESOURCE,
                                            resource_id=lrouter_id),
               cluster=cluster)


def delete_l2_gw_service(cluster, gateway_id):
    do_request("DELETE", _build_uri_path(GWSERVICE_RESOURCE,
                                         resource_id=gateway_id),
               cluster=cluster)


def get_lrouter(cluster, lrouter_id):
    return do_request(HTTP_GET,
                      _build_uri_path(LROUTER_RESOURCE,
                                      resource_id=lrouter_id,
                                      relations='LogicalRouterStatus'),
                      cluster=cluster)


def get_l2_gw_service(cluster, gateway_id):
    return do_request(
        "GET", _build_uri_path(GWSERVICE_RESOURCE,
                               resource_id=gateway_id),
        cluster=cluster)


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
    gwservice_obj["display_name"] = utils.check_and_truncate(display_name)
    return do_request("PUT", _build_uri_path(GWSERVICE_RESOURCE,
                                             resource_id=gateway_id),
                      json.dumps(gwservice_obj), cluster=cluster)


def update_implicit_routing_lrouter(cluster, r_id, display_name, nexthop):
    lrouter_obj = get_lrouter(cluster, r_id)
    if not display_name and not nexthop:
        # Nothing to update
        return lrouter_obj
    # It seems that this is faster than the doing an if on display_name
    lrouter_obj["display_name"] = (utils.check_and_truncate(display_name) or
                                   lrouter_obj["display_name"])
    if nexthop:
        nh_element = lrouter_obj["routing_config"].get(
            "default_route_next_hop")
        if nh_element:
            nh_element["gateway_ip_address"] = nexthop
    return do_request(HTTP_PUT, _build_uri_path(LROUTER_RESOURCE,
                                                resource_id=r_id),
                      json.dumps(lrouter_obj),
                      cluster=cluster)


def get_explicit_routes_lrouter(cluster, router_id, protocol_type='static'):
    static_filter = {'protocol': protocol_type}
    existing_routes = do_request(
        HTTP_GET,
        _build_uri_path(LROUTERRIB_RESOURCE,
                        filters=static_filter,
                        fields="*",
                        parent_resource_id=router_id),
        cluster=cluster)['results']
    return existing_routes


def delete_explicit_route_lrouter(cluster, router_id, route_id):
    do_request(HTTP_DELETE,
               _build_uri_path(LROUTERRIB_RESOURCE,
                               resource_id=route_id,
                               parent_resource_id=router_id),
               cluster=cluster)


def create_explicit_route_lrouter(cluster, router_id, route):
    next_hop_ip = route.get("nexthop") or route.get("next_hop_ip")
    prefix = route.get("destination") or route.get("prefix")
    uuid = do_request(
        HTTP_POST,
        _build_uri_path(LROUTERRIB_RESOURCE,
                        parent_resource_id=router_id),
        json.dumps({
            "action": "accept",
            "next_hop_ip": next_hop_ip,
            "prefix": prefix,
            "protocol": "static"
        }),
        cluster=cluster)['uuid']
    return uuid


def update_explicit_routes_lrouter(cluster, router_id, routes):
    # Update in bulk: delete them all, and add the ones specified
    # but keep track of what is been modified to allow roll-backs
    # in case of failures
    nvp_routes = get_explicit_routes_lrouter(cluster, router_id)
    try:
        deleted_routes = []
        added_routes = []
        # omit the default route (0.0.0.0/0) from the processing;
        # this must be handled through the nexthop for the router
        for route in nvp_routes:
            prefix = route.get("destination") or route.get("prefix")
            if prefix != '0.0.0.0/0':
                delete_explicit_route_lrouter(cluster,
                                              router_id,
                                              route['uuid'])
                deleted_routes.append(route)
        for route in routes:
            prefix = route.get("destination") or route.get("prefix")
            if prefix != '0.0.0.0/0':
                uuid = create_explicit_route_lrouter(cluster,
                                                     router_id, route)
                added_routes.append(uuid)
    except NvpApiClient.NvpApiException:
        LOG.exception(_('Cannot update NVP routes %(routes)s for '
                        'router %(router_id)s'),
                      {'routes': routes, 'router_id': router_id})
        # Roll back to keep NVP in consistent state
        with excutils.save_and_reraise_exception():
            if nvp_routes:
                if deleted_routes:
                    for route in deleted_routes:
                        create_explicit_route_lrouter(cluster,
                                                      router_id, route)
                if added_routes:
                    for route_id in added_routes:
                        delete_explicit_route_lrouter(cluster,
                                                      router_id, route_id)
    return nvp_routes


@version_dependent
def get_default_route_explicit_routing_lrouter(cluster, *args, **kwargs):
    pass


def get_default_route_explicit_routing_lrouter_v33(cluster, router_id):
    static_filter = {"protocol": "static",
                     "prefix": "0.0.0.0/0"}
    default_route = do_request(
        HTTP_GET,
        _build_uri_path(LROUTERRIB_RESOURCE,
                        filters=static_filter,
                        fields="*",
                        parent_resource_id=router_id),
        cluster=cluster)["results"][0]
    return default_route


def get_default_route_explicit_routing_lrouter_v32(cluster, router_id):
    # Scan all routes because 3.2 does not support query by prefix
    all_routes = get_explicit_routes_lrouter(cluster, router_id)
    for route in all_routes:
        if route['prefix'] == '0.0.0.0/0':
            return route


def update_default_gw_explicit_routing_lrouter(cluster, router_id, next_hop):
    default_route = get_default_route_explicit_routing_lrouter(cluster,
                                                               router_id)
    if next_hop != default_route["next_hop_ip"]:
        new_default_route = {"action": "accept",
                             "next_hop_ip": next_hop,
                             "prefix": "0.0.0.0/0",
                             "protocol": "static"}
        do_request(HTTP_PUT,
                   _build_uri_path(LROUTERRIB_RESOURCE,
                                   resource_id=default_route['uuid'],
                                   parent_resource_id=router_id),
                   json.dumps(new_default_route),
                   cluster=cluster)


def update_explicit_routing_lrouter(cluster, router_id,
                                    display_name, next_hop, routes=None):
    update_implicit_routing_lrouter(cluster, router_id, display_name, next_hop)
    if next_hop:
        update_default_gw_explicit_routing_lrouter(cluster,
                                                   router_id, next_hop)
    if routes is not None:
        return update_explicit_routes_lrouter(cluster, router_id, routes)


@version_dependent
def update_lrouter(cluster, *args, **kwargs):
    if kwargs.get('routes', None):
        v = cluster.api_client.get_nvp_version()
        if (v.major, v.minor) < (3, 2):
            raise nvp_exc.NvpInvalidVersion(version=v)
        return v


def delete_network(cluster, net_id, lswitch_id):
    delete_networks(cluster, net_id, [lswitch_id])


#TODO(salvatore-orlando): Simplify and harmonize
def delete_networks(cluster, net_id, lswitch_ids):
    for ls_id in lswitch_ids:
        path = "/ws.v1/lswitch/%s" % ls_id
        try:
            do_request(HTTP_DELETE, path, cluster=cluster)
        except exception.NotFound as e:
            LOG.error(_("Network not found, Error: %s"), str(e))
            raise exception.NetworkNotFound(net_id=ls_id)


def query_lswitch_lports(cluster, ls_uuid, fields="*",
                         filters=None, relations=None):
    # Fix filter for attachments
    if filters and "attachment" in filters:
        filters['attachment_vif_uuid'] = filters["attachment"]
        del filters['attachment']
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, parent_resource_id=ls_uuid,
                          fields=fields, filters=filters, relations=relations)
    return do_request(HTTP_GET, uri, cluster=cluster)['results']


def query_lrouter_lports(cluster, lr_uuid, fields="*",
                         filters=None, relations=None):
    uri = _build_uri_path(LROUTERPORT_RESOURCE, parent_resource_id=lr_uuid,
                          fields=fields, filters=filters, relations=relations)
    return do_request(HTTP_GET, uri, cluster=cluster)['results']


def delete_port(cluster, switch, port):
    uri = "/ws.v1/lswitch/" + switch + "/lport/" + port
    try:
        do_request(HTTP_DELETE, uri, cluster=cluster)
    except exception.NotFound:
        LOG.exception(_("Port or Network not found"))
        raise exception.PortNotFoundOnNetwork(
            net_id=switch, port_id=port)
    except NvpApiClient.NvpApiException:
        raise exception.NeutronException()


def get_ports(cluster, networks=None, devices=None, tenants=None):
    vm_filter_obsolete = ""
    vm_filter = ""
    tenant_filter = ""
    # This is used when calling delete_network. Neutron checks to see if
    # the network has any ports.
    if networks:
        # FIXME (Aaron) If we get more than one network_id this won't work
        lswitch = networks[0]
    else:
        lswitch = "*"
    if devices:
        for device_id in devices:
            vm_filter_obsolete = '&'.join(
                ["tag_scope=vm_id",
                 "tag=%s" % device_id_to_vm_id(device_id, obfuscate=True),
                 vm_filter_obsolete])
            vm_filter = '&'.join(
                ["tag_scope=vm_id",
                 "tag=%s" % device_id_to_vm_id(device_id),
                 vm_filter])
    if tenants:
        for tenant in tenants:
            tenant_filter = '&'.join(
                ["tag_scope=os_tid",
                 "tag=%s" % tenant,
                 tenant_filter])

    nvp_lports = {}
    lport_fields_str = ("tags,admin_status_enabled,display_name,"
                        "fabric_status_up")
    try:
        lport_query_path_obsolete = (
            "/ws.v1/lswitch/%s/lport?fields=%s&%s%stag_scope=q_port_id"
            "&relations=LogicalPortStatus" %
            (lswitch, lport_fields_str, vm_filter_obsolete, tenant_filter))
        lport_query_path = (
            "/ws.v1/lswitch/%s/lport?fields=%s&%s%stag_scope=q_port_id"
            "&relations=LogicalPortStatus" %
            (lswitch, lport_fields_str, vm_filter, tenant_filter))
        try:
            # NOTE(armando-migliaccio): by querying with obsolete tag first
            # current deployments won't take the performance hit of a double
            # call. In release L-** or M-**, we might want to swap the calls
            # as it's likely that ports with the new tag would outnumber the
            # ones with the old tag
            ports = get_all_query_pages(lport_query_path_obsolete, cluster)
            if not ports:
                ports = get_all_query_pages(lport_query_path, cluster)
        except exception.NotFound:
            LOG.warn(_("Lswitch %s not found in NVP"), lswitch)
            ports = None

        if ports:
            for port in ports:
                for tag in port["tags"]:
                    if tag["scope"] == "q_port_id":
                        nvp_lports[tag["tag"]] = port
    except Exception:
        err_msg = _("Unable to get ports")
        LOG.exception(err_msg)
        raise nvp_exc.NvpPluginException(err_msg=err_msg)
    return nvp_lports


def get_port_by_neutron_tag(cluster, lswitch_uuid, neutron_port_id):
    """Get port by neutron tag.

    Returns the NVP UUID of the logical port with tag q_port_id equal to
    neutron_port_id or None if the port is not Found.
    """
    uri = _build_uri_path(LSWITCHPORT_RESOURCE,
                          parent_resource_id=lswitch_uuid,
                          fields='uuid',
                          filters={'tag': neutron_port_id,
                                   'tag_scope': 'q_port_id'})
    LOG.debug(_("Looking for port with q_port_id tag '%(neutron_port_id)s' "
                "on: '%(lswitch_uuid)s'"),
              {'neutron_port_id': neutron_port_id,
               'lswitch_uuid': lswitch_uuid})
    res = do_request(HTTP_GET, uri, cluster=cluster)
    num_results = len(res["results"])
    if num_results >= 1:
        if num_results > 1:
            LOG.warn(_("Found '%(num_ports)d' ports with "
                       "q_port_id tag: '%(neutron_port_id)s'. "
                       "Only 1 was expected."),
                     {'num_ports': num_results,
                      'neutron_port_id': neutron_port_id})
        return res["results"][0]


def get_port(cluster, network, port, relations=None):
    LOG.info(_("get_port() %(network)s %(port)s"),
             {'network': network, 'port': port})
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "?"
    if relations:
        uri += "relations=%s" % relations
    try:
        return do_request(HTTP_GET, uri, cluster=cluster)
    except exception.NotFound as e:
        LOG.error(_("Port or Network not found, Error: %s"), str(e))
        raise exception.PortNotFoundOnNetwork(
            port_id=port, net_id=network)


def _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs):
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
    if mac_learning_enabled is not None:
        lport_obj["mac_learning"] = mac_learning_enabled
        lport_obj["type"] = "LogicalSwitchPortConfig"
    for address_pair in list(allowed_address_pairs or []):
        lport_obj['allowed_address_pairs'].append(
            {'mac_address': address_pair['mac_address'],
             'ip_address': address_pair['ip_address']})


def update_port(cluster, lswitch_uuid, lport_uuid, neutron_port_id, tenant_id,
                display_name, device_id, admin_status_enabled,
                mac_address=None, fixed_ips=None, port_security_enabled=None,
                security_profiles=None, queue_id=None,
                mac_learning_enabled=None, allowed_address_pairs=None):
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=utils.check_and_truncate(display_name),
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=neutron_port_id),
              dict(scope='vm_id', tag=device_id_to_vm_id(device_id)),
              dict(scope='quantum', tag=NEUTRON_VERSION)])

    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs)

    path = "/ws.v1/lswitch/" + lswitch_uuid + "/lport/" + lport_uuid
    try:
        result = do_request(HTTP_PUT, path, json.dumps(lport_obj),
                            cluster=cluster)
        LOG.debug(_("Updated logical port %(result)s "
                    "on logical switch %(uuid)s"),
                  {'result': result['uuid'], 'uuid': lswitch_uuid})
        return result
    except exception.NotFound as e:
        LOG.error(_("Port or Network not found, Error: %s"), str(e))
        raise exception.PortNotFoundOnNetwork(
            port_id=lport_uuid, net_id=lswitch_uuid)


def create_lport(cluster, lswitch_uuid, tenant_id, neutron_port_id,
                 display_name, device_id, admin_status_enabled,
                 mac_address=None, fixed_ips=None, port_security_enabled=None,
                 security_profiles=None, queue_id=None,
                 mac_learning_enabled=None, allowed_address_pairs=None):
    """Creates a logical port on the assigned logical switch."""
    display_name = utils.check_and_truncate(display_name)
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=neutron_port_id),
              dict(scope='vm_id', tag=device_id_to_vm_id(device_id)),
              dict(scope='quantum', tag=NEUTRON_VERSION)],
    )

    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs)

    path = _build_uri_path(LSWITCHPORT_RESOURCE,
                           parent_resource_id=lswitch_uuid)
    result = do_request(HTTP_POST, path, json.dumps(lport_obj),
                        cluster=cluster)

    LOG.debug(_("Created logical port %(result)s on logical switch %(uuid)s"),
              {'result': result['uuid'], 'uuid': lswitch_uuid})
    return result


def create_router_lport(cluster, lrouter_uuid, tenant_id, neutron_port_id,
                        display_name, admin_status_enabled, ip_addresses,
                        mac_address=None):
    """Creates a logical port on the assigned logical router."""
    tags = [dict(scope='os_tid', tag=tenant_id),
            dict(scope='q_port_id', tag=neutron_port_id),
            dict(scope='quantum', tag=NEUTRON_VERSION)]

    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=tags,
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    # Only add the mac_address to lport_obj if present. This is because
    # when creating the fake_ext_gw there is no mac_address present.
    if mac_address:
        lport_obj['mac_address'] = mac_address
    path = _build_uri_path(LROUTERPORT_RESOURCE,
                           parent_resource_id=lrouter_uuid)
    result = do_request(HTTP_POST, path, json.dumps(lport_obj),
                        cluster=cluster)

    LOG.debug(_("Created logical port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': result['uuid'],
               'lrouter_uuid': lrouter_uuid})
    return result


def update_router_lport(cluster, lrouter_uuid, lrouter_port_uuid,
                        tenant_id, neutron_port_id, display_name,
                        admin_status_enabled, ip_addresses):
    """Updates a logical port on the assigned logical router."""
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=[dict(scope='os_tid', tag=tenant_id),
              dict(scope='q_port_id', tag=neutron_port_id),
              dict(scope='quantum', tag=NEUTRON_VERSION)],
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
    result = do_request(HTTP_PUT, path,
                        json.dumps(lport_obj),
                        cluster=cluster)
    LOG.debug(_("Updated logical port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': lrouter_port_uuid, 'lrouter_uuid': lrouter_uuid})
    return result


def delete_router_lport(cluster, lrouter_uuid, lport_uuid):
    """Creates a logical port on the assigned logical router."""
    path = _build_uri_path(LROUTERPORT_RESOURCE, lport_uuid, lrouter_uuid)
    do_request(HTTP_DELETE, path, cluster=cluster)
    LOG.debug(_("Delete logical router port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': lport_uuid,
               'lrouter_uuid': lrouter_uuid})


def delete_peer_router_lport(cluster, lr_uuid, ls_uuid, lp_uuid):
    nvp_port = get_port(cluster, ls_uuid, lp_uuid,
                        relations="LogicalPortAttachment")
    relations = nvp_port.get('_relations')
    if relations:
        att_data = relations.get('LogicalPortAttachment')
        if att_data:
            lrp_uuid = att_data.get('peer_port_uuid')
            if lrp_uuid:
                delete_router_lport(cluster, lr_uuid, lrp_uuid)


def find_router_gw_port(context, cluster, router_id):
    """Retrieves the external gateway port for a NVP logical router."""

    # Find the uuid of nvp ext gw logical router port
    # TODO(salvatore-orlando): Consider storing it in Neutron DB
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
    For the latter attachment type a VLAN ID can be specified as well.
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
        raise nvp_exc.NvpInvalidAttachmentType(
            attachment_type=nvp_attachment_type)
    return do_request(HTTP_PUT, uri, json.dumps(attach_obj), cluster=cluster)


def get_port_status(cluster, lswitch_id, port_id):
    """Retrieve the operational status of the port."""
    try:
        r = do_request(HTTP_GET,
                       "/ws.v1/lswitch/%s/lport/%s/status" %
                       (lswitch_id, port_id), cluster=cluster)
    except exception.NotFound as e:
        LOG.error(_("Port not found, Error: %s"), str(e))
        raise exception.PortNotFoundOnNetwork(
            port_id=port_id, net_id=lswitch_id)
    if r['link_status_up'] is True:
        return constants.PORT_STATUS_ACTIVE
    else:
        return constants.PORT_STATUS_DOWN


def _plug_interface(cluster, lswitch_id, lport_id, att_obj):
    uri = _build_uri_path(LSWITCHPORT_RESOURCE, lport_id, lswitch_id,
                          is_attachment=True)
    return do_request(HTTP_PUT, uri, json.dumps(att_obj),
                      cluster=cluster)


def plug_l2_gw_service(cluster, lswitch_id, lport_id,
                       gateway_id, vlan_id=None):
    """Plug a Layer-2 Gateway Attachment object in a logical port."""
    att_obj = {'type': 'L2GatewayAttachment',
               'l2_gateway_service_uuid': gateway_id}
    if vlan_id:
        att_obj['vlan_id'] = vlan_id
    return _plug_interface(cluster, lswitch_id, lport_id, att_obj)


def plug_interface(cluster, lswitch_id, port, type, attachment=None):
    """Plug a VIF Attachment object in a logical port."""
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
    except exception.NotFound as e:
        # FIXME(salv-orlando): should not raise NeutronException
        LOG.error(format_exception("Unknown", e, locals()))
        raise exception.NeutronException()


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
    return do_request(HTTP_POST, uri, json.dumps(nat_rule_obj),
                      cluster=cluster)


def _build_snat_rule_obj(min_src_ip, max_src_ip, nat_match_obj):
    return {"to_source_ip_address_min": min_src_ip,
            "to_source_ip_address_max": max_src_ip,
            "type": "SourceNatRule",
            "match": nat_match_obj}


def create_lrouter_nosnat_rule_v2(cluster, _router_id, _match_criteria=None):
    LOG.info(_("No SNAT rules cannot be applied as they are not available in "
               "this version of the NVP platform"))


def create_lrouter_nodnat_rule_v2(cluster, _router_id, _match_criteria=None):
    LOG.info(_("No DNAT rules cannot be applied as they are not available in "
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


def create_lrouter_nodnat_rule_v3(cluster, router_id, order=None,
                                  match_criteria=None):
    nat_match_obj = _create_nat_match_obj(**match_criteria)
    nat_rule_obj = {
        "type": "NoDestinationNatRule",
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


@version_dependent
def create_lrouter_nodnat_rule(cluster, *args, **kwargs):
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
    do_request(HTTP_DELETE, uri, cluster=cluster)


def query_nat_rules(cluster, router_id, fields="*", filters=None):
    uri = _build_uri_path(LROUTERNAT_RESOURCE, parent_resource_id=router_id,
                          fields=fields, filters=filters)
    return get_all_query_pages(uri, cluster)


# NOTE(salvatore-orlando): The following FIXME applies in general to
# each operation on list attributes.
# FIXME(salvatore-orlando): need a lock around the list of IPs on an iface
def update_lrouter_port_ips(cluster, lrouter_id, lport_id,
                            ips_to_add, ips_to_remove):
    uri = _build_uri_path(LROUTERPORT_RESOURCE, lport_id, lrouter_id)
    try:
        port = do_request(HTTP_GET, uri, cluster=cluster)
        # TODO(salvatore-orlando): Enforce ips_to_add intersection with
        # ips_to_remove is empty
        ip_address_set = set(port['ip_addresses'])
        ip_address_set = ip_address_set - set(ips_to_remove)
        ip_address_set = ip_address_set | set(ips_to_add)
        # Set is not JSON serializable - convert to list
        port['ip_addresses'] = list(ip_address_set)
        do_request(HTTP_PUT, uri, json.dumps(port), cluster=cluster)
    except exception.NotFound as e:
        # FIXME(salv-orlando):avoid raising different exception
        data = {'lport_id': lport_id, 'lrouter_id': lrouter_id}
        msg = (_("Router Port %(lport_id)s not found on router "
                 "%(lrouter_id)s") % data)
        LOG.exception(msg)
        raise nvp_exc.NvpPluginException(err_msg=msg)
    except NvpApiClient.NvpApiException as e:
        msg = _("An exception occurred while updating IP addresses on a "
                "router logical port:%s") % str(e)
        LOG.exception(msg)
        raise nvp_exc.NvpPluginException(err_msg=msg)


DEFAULT = -1
NVPLIB_FUNC_DICT = {
    'create_lrouter': {
        2: {DEFAULT: create_implicit_routing_lrouter, },
        3: {DEFAULT: create_implicit_routing_lrouter,
            1: create_implicit_routing_lrouter_with_distribution,
            2: create_explicit_routing_lrouter, }, },
    'update_lrouter': {
        2: {DEFAULT: update_implicit_routing_lrouter, },
        3: {DEFAULT: update_implicit_routing_lrouter,
            2: update_explicit_routing_lrouter, }, },
    'create_lrouter_dnat_rule': {
        2: {DEFAULT: create_lrouter_dnat_rule_v2, },
        3: {DEFAULT: create_lrouter_dnat_rule_v3, }, },
    'create_lrouter_snat_rule': {
        2: {DEFAULT: create_lrouter_snat_rule_v2, },
        3: {DEFAULT: create_lrouter_snat_rule_v3, }, },
    'create_lrouter_nosnat_rule': {
        2: {DEFAULT: create_lrouter_nosnat_rule_v2, },
        3: {DEFAULT: create_lrouter_nosnat_rule_v3, }, },
    'create_lrouter_nodnat_rule': {
        2: {DEFAULT: create_lrouter_nodnat_rule_v2, },
        3: {DEFAULT: create_lrouter_nodnat_rule_v3, }, },
    'get_default_route_explicit_routing_lrouter': {
        3: {DEFAULT: get_default_route_explicit_routing_lrouter_v32,
            2: get_default_route_explicit_routing_lrouter_v32, }, },
}


def get_function_by_version(func_name, nvp_ver):
    if nvp_ver:
        if nvp_ver.major not in NVPLIB_FUNC_DICT[func_name]:
            major = max(NVPLIB_FUNC_DICT[func_name].keys())
            minor = max(NVPLIB_FUNC_DICT[func_name][major].keys())
            if major > nvp_ver.major:
                raise NotImplementedError(_("Operation may not be supported"))
        else:
            major = nvp_ver.major
            minor = nvp_ver.minor
            if nvp_ver.minor not in NVPLIB_FUNC_DICT[func_name][major]:
                minor = DEFAULT
        return NVPLIB_FUNC_DICT[func_name][major][minor]
    else:
        msg = _('NVP version is not set. Unable to complete request '
                'correctly. Check log for NVP communication errors.')
        raise NvpApiClient.ServiceUnavailable(message=msg)


# -----------------------------------------------------------------------------
# QOS API Calls
# -----------------------------------------------------------------------------
def create_lqueue(cluster, lqueue):
    uri = _build_uri_path(LQUEUE_RESOURCE)
    lqueue['tags'] = [{'tag': NEUTRON_VERSION, 'scope': 'quantum'}]
    try:
        return do_request(HTTP_POST, uri, json.dumps(lqueue),
                          cluster=cluster)['uuid']
    except NvpApiClient.NvpApiException:
        # FIXME(salv-orlando): This should not raise QauntumException
        LOG.exception(_("Failed to create logical queue"))
        raise exception.NeutronException()


def delete_lqueue(cluster, id):
    try:
        do_request(HTTP_DELETE, _build_uri_path(LQUEUE_RESOURCE,
                                                resource_id=id),
                   cluster=cluster)
    except Exception:
        # FIXME(salv-orlando): This should not raise QauntumException
        LOG.exception(_("Failed to delete logical queue"))
        raise exception.NeutronException()


# -----------------------------------------------------------------------------
# NVP API Calls for check_nvp_config utility
# -----------------------------------------------------------------------------
def config_helper(http_method, http_uri, cluster):
    try:
        return do_request(http_method,
                          http_uri,
                          cluster=cluster)
    except Exception as e:
        msg = (_("Error '%(err)s' when connecting to controller(s): %(ctl)s.")
               % {'err': str(e), 'ctl': ', '.join(cluster.nvp_controllers)})
        raise Exception(msg)


def check_cluster_connectivity(cluster):
    """Make sure that we can issue a request to each of the cluster nodes."""
    return config_helper(HTTP_GET,
                         "/ws.v1/control-cluster",
                         cluster)


def get_gateway_services(cluster):
    return config_helper(HTTP_GET,
                         "/ws.v1/gateway-service?fields=uuid",
                         cluster)


def get_transport_zones(cluster):
    return config_helper(HTTP_GET,
                         "/ws.v1/transport-zone?fields=uuid",
                         cluster)
