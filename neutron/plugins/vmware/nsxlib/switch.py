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
#

from oslo.config import cfg

from neutron.common import constants
from neutron.common import exceptions as exception
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

LSWITCH_RESOURCE = "lswitch"
LSWITCHPORT_RESOURCE = "lport/%s" % LSWITCH_RESOURCE

LOG = log.getLogger(__name__)


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


def get_lswitch_by_id(cluster, lswitch_id):
    try:
        lswitch_uri_path = nsxlib._build_uri_path(
            LSWITCH_RESOURCE, lswitch_id,
            relations="LogicalSwitchStatus")
        return nsxlib.do_request(HTTP_GET, lswitch_uri_path, cluster=cluster)
    except exception.NotFound:
        # FIXME(salv-orlando): this should not raise a neutron exception
        raise exception.NetworkNotFound(net_id=lswitch_id)


def get_lswitches(cluster, neutron_net_id):

    def lookup_switches_by_tag():
        # Fetch extra logical switches
        lswitch_query_path = nsxlib._build_uri_path(
            LSWITCH_RESOURCE,
            fields="uuid,display_name,tags,lport_count",
            relations="LogicalSwitchStatus",
            filters={'tag': neutron_net_id,
                     'tag_scope': 'quantum_net_id'})
        return nsxlib.get_all_query_pages(lswitch_query_path, cluster)

    lswitch_uri_path = nsxlib._build_uri_path(LSWITCH_RESOURCE, neutron_net_id,
                                              relations="LogicalSwitchStatus")
    results = []
    try:
        ls = nsxlib.do_request(HTTP_GET, lswitch_uri_path, cluster=cluster)
        results.append(ls)
        for tag in ls['tags']:
            if (tag['scope'] == "multi_lswitch" and
                tag['tag'] == "True"):
                results.extend(lookup_switches_by_tag())
    except exception.NotFound:
        # This is legit if the neutron network was created using
        # a post-Havana version of the plugin
        results.extend(lookup_switches_by_tag())
    if results:
        return results
    else:
        raise exception.NetworkNotFound(net_id=neutron_net_id)


def create_lswitch(cluster, neutron_net_id, tenant_id, display_name,
                   transport_zones_config,
                   shared=None,
                   **kwargs):
    # The tag scope adopts a slightly different naming convention for
    # historical reasons
    lswitch_obj = {"display_name": utils.check_and_truncate(display_name),
                   "transport_zones": transport_zones_config,
                   "replication_mode": cfg.CONF.NSX.replication_mode,
                   "tags": utils.get_tags(os_tid=tenant_id,
                                          quantum_net_id=neutron_net_id)}
    # TODO(salv-orlando): Now that we have async status synchronization
    # this tag is perhaps not needed anymore
    if shared:
        lswitch_obj["tags"].append({"tag": "true",
                                    "scope": "shared"})
    if "tags" in kwargs:
        lswitch_obj["tags"].extend(kwargs["tags"])
    uri = nsxlib._build_uri_path(LSWITCH_RESOURCE)
    lswitch = nsxlib.do_request(HTTP_POST, uri, jsonutils.dumps(lswitch_obj),
                                cluster=cluster)
    LOG.debug(_("Created logical switch: %s"), lswitch['uuid'])
    return lswitch


def update_lswitch(cluster, lswitch_id, display_name,
                   tenant_id=None, **kwargs):
    uri = nsxlib._build_uri_path(LSWITCH_RESOURCE, resource_id=lswitch_id)
    lswitch_obj = {"display_name": utils.check_and_truncate(display_name)}
    # NOTE: tag update will not 'merge' existing tags with new ones.
    tags = []
    if tenant_id:
        tags = utils.get_tags(os_tid=tenant_id)
    # The 'tags' kwarg might existing and be None
    tags.extend(kwargs.get('tags') or [])
    if tags:
        lswitch_obj['tags'] = tags
    try:
        return nsxlib.do_request(HTTP_PUT, uri, jsonutils.dumps(lswitch_obj),
                                 cluster=cluster)
    except exception.NotFound as e:
        LOG.error(_("Network not found, Error: %s"), str(e))
        raise exception.NetworkNotFound(net_id=lswitch_id)


def delete_network(cluster, net_id, lswitch_id):
    delete_networks(cluster, net_id, [lswitch_id])


#TODO(salvatore-orlando): Simplify and harmonize
def delete_networks(cluster, net_id, lswitch_ids):
    for ls_id in lswitch_ids:
        path = "/ws.v1/lswitch/%s" % ls_id
        try:
            nsxlib.do_request(HTTP_DELETE, path, cluster=cluster)
        except exception.NotFound as e:
            LOG.error(_("Network not found, Error: %s"), str(e))
            raise exception.NetworkNotFound(net_id=ls_id)


def query_lswitch_lports(cluster, ls_uuid, fields="*",
                         filters=None, relations=None):
    # Fix filter for attachments
    if filters and "attachment" in filters:
        filters['attachment_vif_uuid'] = filters["attachment"]
        del filters['attachment']
    uri = nsxlib._build_uri_path(LSWITCHPORT_RESOURCE,
                                 parent_resource_id=ls_uuid,
                                 fields=fields,
                                 filters=filters,
                                 relations=relations)
    return nsxlib.do_request(HTTP_GET, uri, cluster=cluster)['results']


def delete_port(cluster, switch, port):
    uri = "/ws.v1/lswitch/" + switch + "/lport/" + port
    try:
        nsxlib.do_request(HTTP_DELETE, uri, cluster=cluster)
    except exception.NotFound:
        LOG.exception(_("Port or Network not found"))
        raise exception.PortNotFoundOnNetwork(
            net_id=switch, port_id=port)
    except api_exc.NsxApiException:
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
                 "tag=%s" % utils.device_id_to_vm_id(device_id,
                                                     obfuscate=True),
                 vm_filter_obsolete])
            vm_filter = '&'.join(
                ["tag_scope=vm_id",
                 "tag=%s" % utils.device_id_to_vm_id(device_id),
                 vm_filter])
    if tenants:
        for tenant in tenants:
            tenant_filter = '&'.join(
                ["tag_scope=os_tid",
                 "tag=%s" % tenant,
                 tenant_filter])

    nsx_lports = {}
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
            ports = nsxlib.get_all_query_pages(lport_query_path_obsolete,
                                               cluster)
            if not ports:
                ports = nsxlib.get_all_query_pages(lport_query_path, cluster)
        except exception.NotFound:
            LOG.warn(_("Lswitch %s not found in NSX"), lswitch)
            ports = None

        if ports:
            for port in ports:
                for tag in port["tags"]:
                    if tag["scope"] == "q_port_id":
                        nsx_lports[tag["tag"]] = port
    except Exception:
        err_msg = _("Unable to get ports")
        LOG.exception(err_msg)
        raise nsx_exc.NsxPluginException(err_msg=err_msg)
    return nsx_lports


def get_port_by_neutron_tag(cluster, lswitch_uuid, neutron_port_id):
    """Get port by neutron tag.

    Returns the NSX UUID of the logical port with tag q_port_id equal to
    neutron_port_id or None if the port is not Found.
    """
    uri = nsxlib._build_uri_path(LSWITCHPORT_RESOURCE,
                                 parent_resource_id=lswitch_uuid,
                                 fields='uuid',
                                 filters={'tag': neutron_port_id,
                                          'tag_scope': 'q_port_id'})
    LOG.debug(_("Looking for port with q_port_id tag '%(neutron_port_id)s' "
                "on: '%(lswitch_uuid)s'"),
              {'neutron_port_id': neutron_port_id,
               'lswitch_uuid': lswitch_uuid})
    res = nsxlib.do_request(HTTP_GET, uri, cluster=cluster)
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
        return nsxlib.do_request(HTTP_GET, uri, cluster=cluster)
    except exception.NotFound as e:
        LOG.error(_("Port or Network not found, Error: %s"), str(e))
        raise exception.PortNotFoundOnNetwork(
            port_id=port, net_id=network)


def update_port(cluster, lswitch_uuid, lport_uuid, neutron_port_id, tenant_id,
                display_name, device_id, admin_status_enabled,
                mac_address=None, fixed_ips=None, port_security_enabled=None,
                security_profiles=None, queue_id=None,
                mac_learning_enabled=None, allowed_address_pairs=None):
    lport_obj = dict(
        admin_status_enabled=admin_status_enabled,
        display_name=utils.check_and_truncate(display_name),
        tags=utils.get_tags(os_tid=tenant_id,
                            q_port_id=neutron_port_id,
                            vm_id=utils.device_id_to_vm_id(device_id)))

    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs)

    path = "/ws.v1/lswitch/" + lswitch_uuid + "/lport/" + lport_uuid
    try:
        result = nsxlib.do_request(HTTP_PUT, path, jsonutils.dumps(lport_obj),
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
        tags=utils.get_tags(os_tid=tenant_id,
                            q_port_id=neutron_port_id,
                            vm_id=utils.device_id_to_vm_id(device_id))
    )

    _configure_extensions(lport_obj, mac_address, fixed_ips,
                          port_security_enabled, security_profiles,
                          queue_id, mac_learning_enabled,
                          allowed_address_pairs)

    path = nsxlib._build_uri_path(LSWITCHPORT_RESOURCE,
                                  parent_resource_id=lswitch_uuid)
    result = nsxlib.do_request(HTTP_POST, path, jsonutils.dumps(lport_obj),
                               cluster=cluster)

    LOG.debug(_("Created logical port %(result)s on logical switch %(uuid)s"),
              {'result': result['uuid'], 'uuid': lswitch_uuid})
    return result


def get_port_status(cluster, lswitch_id, port_id):
    """Retrieve the operational status of the port."""
    try:
        r = nsxlib.do_request(HTTP_GET,
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


def plug_interface(cluster, lswitch_id, lport_id, att_obj):
    return nsxlib.do_request(HTTP_PUT,
                             nsxlib._build_uri_path(LSWITCHPORT_RESOURCE,
                                                    lport_id, lswitch_id,
                                                    is_attachment=True),
                             jsonutils.dumps(att_obj),
                             cluster=cluster)


def plug_vif_interface(
    cluster, lswitch_id, port_id, port_type, attachment=None):
    """Plug a VIF Attachment object in a logical port."""
    lport_obj = {}
    if attachment:
        lport_obj["vif_uuid"] = attachment

    lport_obj["type"] = port_type
    return plug_interface(cluster, lswitch_id, port_id, lport_obj)
