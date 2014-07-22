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

from oslo.config import cfg

from neutron.common import exceptions as exception
from neutron.openstack.common import excutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib
from neutron.plugins.vmware.nsxlib import switch
from neutron.plugins.vmware.nsxlib import versioning

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

LROUTER_RESOURCE = "lrouter"
LROUTER_RESOURCE = "lrouter"
LROUTERPORT_RESOURCE = "lport/%s" % LROUTER_RESOURCE
LROUTERRIB_RESOURCE = "rib/%s" % LROUTER_RESOURCE
LROUTERNAT_RESOURCE = "nat/lrouter"
# Constants for NAT rules
MATCH_KEYS = ["destination_ip_addresses", "destination_port_max",
              "destination_port_min", "source_ip_addresses",
              "source_port_max", "source_port_min", "protocol"]

LOG = log.getLogger(__name__)


def _prepare_lrouter_body(name, neutron_router_id, tenant_id,
                          router_type, distributed=None, **kwargs):
    body = {
        "display_name": utils.check_and_truncate(name),
        "tags": utils.get_tags(os_tid=tenant_id,
                               q_router_id=neutron_router_id),
        "routing_config": {
            "type": router_type
        },
        "type": "LogicalRouterConfig",
        "replication_mode": cfg.CONF.NSX.replication_mode,
    }
    # add the distributed key only if not None (ie: True or False)
    if distributed is not None:
        body['distributed'] = distributed
    if kwargs:
        body["routing_config"].update(kwargs)
    return body


def _create_implicit_routing_lrouter(cluster, neutron_router_id, tenant_id,
                                     display_name, nexthop, distributed=None):
    implicit_routing_config = {
        "default_route_next_hop": {
            "gateway_ip_address": nexthop,
            "type": "RouterNextHop"
        },
    }
    lrouter_obj = _prepare_lrouter_body(
        display_name, neutron_router_id, tenant_id,
        "SingleDefaultRouteImplicitRoutingConfig",
        distributed=distributed,
        **implicit_routing_config)
    return nsxlib.do_request(HTTP_POST,
                             nsxlib._build_uri_path(LROUTER_RESOURCE),
                             jsonutils.dumps(lrouter_obj), cluster=cluster)


def create_implicit_routing_lrouter(cluster, neutron_router_id, tenant_id,
                                    display_name, nexthop):
    """Create a NSX logical router on the specified cluster.

        :param cluster: The target NSX cluster
        :param tenant_id: Identifier of the Openstack tenant for which
        the logical router is being created
        :param display_name: Descriptive name of this logical router
        :param nexthop: External gateway IP address for the logical router
        :raise NsxApiException: if there is a problem while communicating
        with the NSX controller
    """
    return _create_implicit_routing_lrouter(
        cluster, neutron_router_id, tenant_id, display_name, nexthop)


def create_implicit_routing_lrouter_with_distribution(
    cluster, neutron_router_id, tenant_id, display_name,
    nexthop, distributed=None):
    """Create a NSX logical router on the specified cluster.

    This function also allows for creating distributed lrouters
    :param cluster: The target NSX cluster
    :param tenant_id: Identifier of the Openstack tenant for which
    the logical router is being created
    :param display_name: Descriptive name of this logical router
    :param nexthop: External gateway IP address for the logical router
    :param distributed: True for distributed logical routers
    :raise NsxApiException: if there is a problem while communicating
    with the NSX controller
    """
    return _create_implicit_routing_lrouter(
        cluster, neutron_router_id, tenant_id,
        display_name, nexthop, distributed)


def create_explicit_routing_lrouter(cluster, neutron_router_id, tenant_id,
                                    display_name, nexthop, distributed=None):
    lrouter_obj = _prepare_lrouter_body(
        display_name, neutron_router_id, tenant_id,
        "RoutingTableRoutingConfig", distributed=distributed)
    router = nsxlib.do_request(HTTP_POST,
                               nsxlib._build_uri_path(LROUTER_RESOURCE),
                               jsonutils.dumps(lrouter_obj), cluster=cluster)
    default_gw = {'prefix': '0.0.0.0/0', 'next_hop_ip': nexthop}
    create_explicit_route_lrouter(cluster, router['uuid'], default_gw)
    return router


def delete_lrouter(cluster, lrouter_id):
    nsxlib.do_request(HTTP_DELETE,
                      nsxlib._build_uri_path(LROUTER_RESOURCE,
                                             resource_id=lrouter_id),
                      cluster=cluster)


def get_lrouter(cluster, lrouter_id):
    return nsxlib.do_request(HTTP_GET,
                             nsxlib._build_uri_path(
                                 LROUTER_RESOURCE,
                                 resource_id=lrouter_id,
                                 relations='LogicalRouterStatus'),
                             cluster=cluster)


def query_lrouters(cluster, fields=None, filters=None):
    return nsxlib.get_all_query_pages(
        nsxlib._build_uri_path(LROUTER_RESOURCE,
                               fields=fields,
                               relations='LogicalRouterStatus',
                               filters=filters),
        cluster)


def get_lrouters(cluster, tenant_id, fields=None, filters=None):
    # FIXME(salv-orlando): Fields parameter is ignored in this routine
    actual_filters = {}
    if filters:
        actual_filters.update(filters)
    if tenant_id:
        actual_filters['tag'] = tenant_id
        actual_filters['tag_scope'] = 'os_tid'
    lrouter_fields = "uuid,display_name,fabric_status,tags"
    return query_lrouters(cluster, lrouter_fields, actual_filters)


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
    return nsxlib.do_request(HTTP_PUT,
                             nsxlib._build_uri_path(LROUTER_RESOURCE,
                                                    resource_id=r_id),
                             jsonutils.dumps(lrouter_obj),
                             cluster=cluster)


def get_explicit_routes_lrouter(cluster, router_id, protocol_type='static'):
    static_filter = {'protocol': protocol_type}
    existing_routes = nsxlib.do_request(
        HTTP_GET,
        nsxlib._build_uri_path(LROUTERRIB_RESOURCE,
                               filters=static_filter,
                               fields="*",
                               parent_resource_id=router_id),
        cluster=cluster)['results']
    return existing_routes


def delete_explicit_route_lrouter(cluster, router_id, route_id):
    nsxlib.do_request(HTTP_DELETE,
                      nsxlib._build_uri_path(LROUTERRIB_RESOURCE,
                                             resource_id=route_id,
                                             parent_resource_id=router_id),
                      cluster=cluster)


def create_explicit_route_lrouter(cluster, router_id, route):
    next_hop_ip = route.get("nexthop") or route.get("next_hop_ip")
    prefix = route.get("destination") or route.get("prefix")
    uuid = nsxlib.do_request(
        HTTP_POST,
        nsxlib._build_uri_path(LROUTERRIB_RESOURCE,
                               parent_resource_id=router_id),
        jsonutils.dumps({
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
    nsx_routes = get_explicit_routes_lrouter(cluster, router_id)
    try:
        deleted_routes = []
        added_routes = []
        # omit the default route (0.0.0.0/0) from the processing;
        # this must be handled through the nexthop for the router
        for route in nsx_routes:
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
    except api_exc.NsxApiException:
        LOG.exception(_('Cannot update NSX routes %(routes)s for '
                        'router %(router_id)s'),
                      {'routes': routes, 'router_id': router_id})
        # Roll back to keep NSX in consistent state
        with excutils.save_and_reraise_exception():
            if nsx_routes:
                if deleted_routes:
                    for route in deleted_routes:
                        create_explicit_route_lrouter(cluster,
                                                      router_id, route)
                if added_routes:
                    for route_id in added_routes:
                        delete_explicit_route_lrouter(cluster,
                                                      router_id, route_id)
    return nsx_routes


def get_default_route_explicit_routing_lrouter_v33(cluster, router_id):
    static_filter = {"protocol": "static",
                     "prefix": "0.0.0.0/0"}
    default_route = nsxlib.do_request(
        HTTP_GET,
        nsxlib._build_uri_path(LROUTERRIB_RESOURCE,
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
        nsxlib.do_request(HTTP_PUT,
                          nsxlib._build_uri_path(
                              LROUTERRIB_RESOURCE,
                              resource_id=default_route['uuid'],
                              parent_resource_id=router_id),
                          jsonutils.dumps(new_default_route),
                          cluster=cluster)


def update_explicit_routing_lrouter(cluster, router_id,
                                    display_name, next_hop, routes=None):
    update_implicit_routing_lrouter(cluster, router_id, display_name, next_hop)
    if next_hop:
        update_default_gw_explicit_routing_lrouter(cluster,
                                                   router_id, next_hop)
    if routes is not None:
        return update_explicit_routes_lrouter(cluster, router_id, routes)


def query_lrouter_lports(cluster, lr_uuid, fields="*",
                         filters=None, relations=None):
    uri = nsxlib._build_uri_path(LROUTERPORT_RESOURCE,
                                 parent_resource_id=lr_uuid,
                                 fields=fields, filters=filters,
                                 relations=relations)
    return nsxlib.do_request(HTTP_GET, uri, cluster=cluster)['results']


def create_router_lport(cluster, lrouter_uuid, tenant_id, neutron_port_id,
                        display_name, admin_status_enabled, ip_addresses,
                        mac_address=None):
    """Creates a logical port on the assigned logical router."""
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=display_name,
        tags=utils.get_tags(os_tid=tenant_id, q_port_id=neutron_port_id),
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    # Only add the mac_address to lport_obj if present. This is because
    # when creating the fake_ext_gw there is no mac_address present.
    if mac_address:
        lport_obj['mac_address'] = mac_address
    path = nsxlib._build_uri_path(LROUTERPORT_RESOURCE,
                                  parent_resource_id=lrouter_uuid)
    result = nsxlib.do_request(HTTP_POST, path, jsonutils.dumps(lport_obj),
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
        tags=utils.get_tags(os_tid=tenant_id, q_port_id=neutron_port_id),
        ip_addresses=ip_addresses,
        type="LogicalRouterPortConfig"
    )
    # Do not pass null items to NSX
    for key in lport_obj.keys():
        if lport_obj[key] is None:
            del lport_obj[key]
    path = nsxlib._build_uri_path(LROUTERPORT_RESOURCE,
                                  lrouter_port_uuid,
                                  parent_resource_id=lrouter_uuid)
    result = nsxlib.do_request(HTTP_PUT, path,
                               jsonutils.dumps(lport_obj),
                               cluster=cluster)
    LOG.debug(_("Updated logical port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': lrouter_port_uuid, 'lrouter_uuid': lrouter_uuid})
    return result


def delete_router_lport(cluster, lrouter_uuid, lport_uuid):
    """Creates a logical port on the assigned logical router."""
    path = nsxlib._build_uri_path(LROUTERPORT_RESOURCE, lport_uuid,
                                  lrouter_uuid)
    nsxlib.do_request(HTTP_DELETE, path, cluster=cluster)
    LOG.debug(_("Delete logical router port %(lport_uuid)s on "
                "logical router %(lrouter_uuid)s"),
              {'lport_uuid': lport_uuid,
               'lrouter_uuid': lrouter_uuid})


def delete_peer_router_lport(cluster, lr_uuid, ls_uuid, lp_uuid):
    nsx_port = switch.get_port(cluster, ls_uuid, lp_uuid,
                               relations="LogicalPortAttachment")
    relations = nsx_port.get('_relations')
    if relations:
        att_data = relations.get('LogicalPortAttachment')
        if att_data:
            lrp_uuid = att_data.get('peer_port_uuid')
            if lrp_uuid:
                delete_router_lport(cluster, lr_uuid, lrp_uuid)


def find_router_gw_port(context, cluster, router_id):
    """Retrieves the external gateway port for a NSX logical router."""

    # Find the uuid of nsx ext gw logical router port
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
                                attachment_uuid, nsx_attachment_type,
                                attachment_vlan=None):
    """Attach a router port to the given attachment.

    Current attachment types:
       - PatchAttachment [-> logical switch port uuid]
       - L3GatewayAttachment [-> L3GatewayService uuid]
    For the latter attachment type a VLAN ID can be specified as well.
    """
    uri = nsxlib._build_uri_path(LROUTERPORT_RESOURCE, port_id, router_id,
                                 is_attachment=True)
    attach_obj = {}
    attach_obj["type"] = nsx_attachment_type
    if nsx_attachment_type == "PatchAttachment":
        attach_obj["peer_port_uuid"] = attachment_uuid
    elif nsx_attachment_type == "L3GatewayAttachment":
        attach_obj["l3_gateway_service_uuid"] = attachment_uuid
        if attachment_vlan:
            attach_obj['vlan_id'] = attachment_vlan
    else:
        raise nsx_exc.InvalidAttachmentType(
            attachment_type=nsx_attachment_type)
    return nsxlib.do_request(
        HTTP_PUT, uri, jsonutils.dumps(attach_obj), cluster=cluster)


def _create_nat_match_obj(**kwargs):
    nat_match_obj = {'ethertype': 'IPv4'}
    delta = set(kwargs.keys()) - set(MATCH_KEYS)
    if delta:
        raise Exception(_("Invalid keys for NAT match: %s"), delta)
    nat_match_obj.update(kwargs)
    return nat_match_obj


def _create_lrouter_nat_rule(cluster, router_id, nat_rule_obj):
    LOG.debug(_("Creating NAT rule: %s"), nat_rule_obj)
    uri = nsxlib._build_uri_path(LROUTERNAT_RESOURCE,
                                 parent_resource_id=router_id)
    return nsxlib.do_request(HTTP_POST, uri, jsonutils.dumps(nat_rule_obj),
                             cluster=cluster)


def _build_snat_rule_obj(min_src_ip, max_src_ip, nat_match_obj):
    return {"to_source_ip_address_min": min_src_ip,
            "to_source_ip_address_max": max_src_ip,
            "type": "SourceNatRule",
            "match": nat_match_obj}


def create_lrouter_nosnat_rule_v2(cluster, _router_id, _match_criteria=None):
    LOG.info(_("No SNAT rules cannot be applied as they are not available in "
               "this version of the NSX platform"))


def create_lrouter_nodnat_rule_v2(cluster, _router_id, _match_criteria=None):
    LOG.info(_("No DNAT rules cannot be applied as they are not available in "
               "this version of the NSX platform"))


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


def delete_nat_rules_by_match(cluster, router_id, rule_type,
                              max_num_expected,
                              min_num_expected=0,
                              raise_on_len_mismatch=True,
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
    num_rules_to_delete = len(to_delete_ids)
    if (num_rules_to_delete < min_num_expected or
        num_rules_to_delete > max_num_expected):
        if raise_on_len_mismatch:
            raise nsx_exc.NatRuleMismatch(actual_rules=num_rules_to_delete,
                                          min_rules=min_num_expected,
                                          max_rules=max_num_expected)
        else:
            LOG.warn(_("Found %(actual_rule_num)d matching NAT rules, which "
                       "is not in the expected range (%(min_exp_rule_num)d,"
                       "%(max_exp_rule_num)d)"),
                     {'actual_rule_num': num_rules_to_delete,
                      'min_exp_rule_num': min_num_expected,
                      'max_exp_rule_num': max_num_expected})

    for rule_id in to_delete_ids:
        delete_router_nat_rule(cluster, router_id, rule_id)
    # Return number of deleted rules - useful at least for
    # testing purposes
    return num_rules_to_delete


def delete_router_nat_rule(cluster, router_id, rule_id):
    uri = nsxlib._build_uri_path(LROUTERNAT_RESOURCE, rule_id, router_id)
    nsxlib.do_request(HTTP_DELETE, uri, cluster=cluster)


def query_nat_rules(cluster, router_id, fields="*", filters=None):
    uri = nsxlib._build_uri_path(LROUTERNAT_RESOURCE,
                                 parent_resource_id=router_id,
                                 fields=fields, filters=filters)
    return nsxlib.get_all_query_pages(uri, cluster)


# NOTE(salvatore-orlando): The following FIXME applies in general to
# each operation on list attributes.
# FIXME(salvatore-orlando): need a lock around the list of IPs on an iface
def update_lrouter_port_ips(cluster, lrouter_id, lport_id,
                            ips_to_add, ips_to_remove):
    uri = nsxlib._build_uri_path(LROUTERPORT_RESOURCE, lport_id, lrouter_id)
    try:
        port = nsxlib.do_request(HTTP_GET, uri, cluster=cluster)
        # TODO(salvatore-orlando): Enforce ips_to_add intersection with
        # ips_to_remove is empty
        ip_address_set = set(port['ip_addresses'])
        ip_address_set = ip_address_set - set(ips_to_remove)
        ip_address_set = ip_address_set | set(ips_to_add)
        # Set is not JSON serializable - convert to list
        port['ip_addresses'] = list(ip_address_set)
        nsxlib.do_request(HTTP_PUT, uri, jsonutils.dumps(port),
                          cluster=cluster)
    except exception.NotFound:
        # FIXME(salv-orlando):avoid raising different exception
        data = {'lport_id': lport_id, 'lrouter_id': lrouter_id}
        msg = (_("Router Port %(lport_id)s not found on router "
                 "%(lrouter_id)s") % data)
        LOG.exception(msg)
        raise nsx_exc.NsxPluginException(err_msg=msg)
    except api_exc.NsxApiException as e:
        msg = _("An exception occurred while updating IP addresses on a "
                "router logical port:%s") % str(e)
        LOG.exception(msg)
        raise nsx_exc.NsxPluginException(err_msg=msg)


ROUTER_FUNC_DICT = {
    'create_lrouter': {
        2: {versioning.DEFAULT_VERSION: create_implicit_routing_lrouter, },
        3: {versioning.DEFAULT_VERSION: create_implicit_routing_lrouter,
            1: create_implicit_routing_lrouter_with_distribution,
            2: create_explicit_routing_lrouter, }, },
    'update_lrouter': {
        2: {versioning.DEFAULT_VERSION: update_implicit_routing_lrouter, },
        3: {versioning.DEFAULT_VERSION: update_implicit_routing_lrouter,
            2: update_explicit_routing_lrouter, }, },
    'create_lrouter_dnat_rule': {
        2: {versioning.DEFAULT_VERSION: create_lrouter_dnat_rule_v2, },
        3: {versioning.DEFAULT_VERSION: create_lrouter_dnat_rule_v3, }, },
    'create_lrouter_snat_rule': {
        2: {versioning.DEFAULT_VERSION: create_lrouter_snat_rule_v2, },
        3: {versioning.DEFAULT_VERSION: create_lrouter_snat_rule_v3, }, },
    'create_lrouter_nosnat_rule': {
        2: {versioning.DEFAULT_VERSION: create_lrouter_nosnat_rule_v2, },
        3: {versioning.DEFAULT_VERSION: create_lrouter_nosnat_rule_v3, }, },
    'create_lrouter_nodnat_rule': {
        2: {versioning.DEFAULT_VERSION: create_lrouter_nodnat_rule_v2, },
        3: {versioning.DEFAULT_VERSION: create_lrouter_nodnat_rule_v3, }, },
    'get_default_route_explicit_routing_lrouter': {
        3: {versioning.DEFAULT_VERSION:
            get_default_route_explicit_routing_lrouter_v32,
            2: get_default_route_explicit_routing_lrouter_v32, }, },
}


@versioning.versioned(ROUTER_FUNC_DICT)
def create_lrouter(cluster, *args, **kwargs):
    if kwargs.get('distributed', None):
        v = cluster.api_client.get_version()
        if (v.major, v.minor) < (3, 1):
            raise nsx_exc.InvalidVersion(version=v)
        return v


@versioning.versioned(ROUTER_FUNC_DICT)
def get_default_route_explicit_routing_lrouter(cluster, *args, **kwargs):
    pass


@versioning.versioned(ROUTER_FUNC_DICT)
def update_lrouter(cluster, *args, **kwargs):
    if kwargs.get('routes', None):
        v = cluster.api_client.get_version()
        if (v.major, v.minor) < (3, 2):
            raise nsx_exc.InvalidVersion(version=v)
        return v


@versioning.versioned(ROUTER_FUNC_DICT)
def create_lrouter_dnat_rule(cluster, *args, **kwargs):
    pass


@versioning.versioned(ROUTER_FUNC_DICT)
def create_lrouter_snat_rule(cluster, *args, **kwargs):
    pass


@versioning.versioned(ROUTER_FUNC_DICT)
def create_lrouter_nosnat_rule(cluster, *args, **kwargs):
    pass


@versioning.versioned(ROUTER_FUNC_DICT)
def create_lrouter_nodnat_rule(cluster, *args, **kwargs):
    pass
