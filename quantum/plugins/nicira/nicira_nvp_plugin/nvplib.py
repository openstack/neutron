# Copyright 2012 Nicira Networks, Inc.
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

from quantum.common import exceptions as exception
import json
import logging
import NvpApiClient

LOG = logging.getLogger("nvplib")
LOG.setLevel(logging.INFO)


def do_single_request(*args, **kwargs):
    """Issue a request to a specified controller if specified via kwargs
       (controller=<controller>)."""
    controller = kwargs["controller"]
    LOG.debug("Issuing request to controller: %s" % controller.name)
    return controller.api_client.request(*args)


def check_default_transport_zone(c):
    """Make sure the default transport zone specified in the config exists"""
    msg = []
    # This will throw an exception on failure and that's ok since it will
    # just propogate to the cli.
    resp = do_single_request("GET",
        "/ws.v1/transport-zone?uuid=%s" % c.default_tz_uuid,
        controller=c)
    result = json.loads(resp)
    if int(result["result_count"]) == 0:
        msg.append("Unable to find zone \"%s\" for controller \"%s\"" %
            (c.default_tz_uuid, c.name))
    if len(msg) > 0:
        raise Exception(' '.join(msg))


def check_tenant(controller, net_id, tenant_id):
    """Return true if the tenant "owns" this network"""
    net = get_network(controller, net_id)
    for t in net["tags"]:
        if t["scope"] == "os_tid" and t["tag"] == tenant_id:
            return True
    return False

# -------------------------------------------------------------------
# Network functions
# -------------------------------------------------------------------


def get_network(controller, net_id):
    path = "/ws.v1/lswitch/%s" % net_id
    try:
        resp_obj = do_single_request("GET", path, controller=controller)
        network = json.loads(resp_obj)
    except NvpApiClient.ResourceNotFound as e:
        raise exception.NetworkNotFound(net_id=net_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    LOG.debug("Got network \"%s\": %s" % (net_id, network))
    return network


def create_lswitch(controller, lswitch_obj):
    LOG.debug("Creating lswitch: %s" % lswitch_obj)
    # Warn if no tenant is specified
    found = "os_tid" in [x["scope"] for x in lswitch_obj["tags"]]
    if not found:
        LOG.warn("No tenant-id tag specified in logical switch: %s" % (
            lswitch_obj))
    uri = "/ws.v1/lswitch"
    try:
        resp_obj = do_single_request("POST", uri,
                                     json.dumps(lswitch_obj),
                                     controller=controller)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    r = json.loads(resp_obj)
    d = {}
    d["net-id"] = r["uuid"]
    d["net-name"] = r["display_name"]
    LOG.debug("Created logical switch: %s" % d["net-id"])
    return d


def update_network(controller, network, **kwargs):
    uri = "/ws.v1/lswitch/" + network
    lswitch_obj = {}
    if "name" in kwargs:
        lswitch_obj["display_name"] = kwargs["name"]
    try:
        resp_obj = do_single_request("PUT", uri,
          json.dumps(lswitch_obj), controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    return obj


def get_all_networks(controller, tenant_id, networks):
    """Append the quantum network uuids we can find in the given controller to
       "networks"
       """
    uri = "/ws.v1/lswitch?fields=*&tag=%s&tag_scope=os_tid" % tenant_id
    try:
        resp_obj = do_single_request("GET", uri, controller=controller)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    lswitches = json.loads(resp_obj)["results"]
    for lswitch in lswitches:
        net_id = lswitch["uuid"]
        if net_id not in [x["net-id"] for x in networks]:
            networks.append({"net-id": net_id,
                             "net-name": lswitch["display_name"]})
    return networks


def query_networks(controller, tenant_id, fields="*", tags=None):
    uri = "/ws.v1/lswitch?fields=%s" % fields
    if tags:
        for t in tags:
            uri += "&tag=%s&tag_scope=%s" % (t[0], t[1])
    try:
        resp_obj = do_single_request("GET", uri, controller=controller)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    if not resp_obj:
        return []
    lswitches = json.loads(resp_obj)["results"]
    nets = [{'net-id': lswitch["uuid"],
             'net-name': lswitch["display_name"]}
             for lswitch in lswitches]
    return nets


def delete_network(controller, network):
    delete_networks(controller, [network])


def delete_networks(controller, networks):
    for network in networks:
        path = "/ws.v1/lswitch/%s" % network

        try:
            do_single_request("DELETE", path, controller=controller)
        except NvpApiClient.ResourceNotFound as e:
            LOG.error("Network not found, Error: %s" % str(e))
            raise exception.NetworkNotFound(net_id=network)
        except NvpApiClient.NvpApiException as e:
            raise exception.QuantumException()


def create_network(tenant_id, net_name, **kwargs):
    controller = kwargs["controller"]

    transport_zone = kwargs.get("transport_zone",
      controller.default_tz_uuid)
    transport_type = kwargs.get("transport_type", "gre")
    lswitch_obj = {"display_name": net_name,
                   "transport_zones": [
                    {"zone_uuid": transport_zone,
                     "transport_type": transport_type}
                   ],
                "tags": [{"tag": tenant_id, "scope": "os_tid"}]
             }

    net = create_lswitch(controller, lswitch_obj)
    net['net-op-status'] = "UP"
    return net

#---------------------------------------------------------------------
# Port functions
#---------------------------------------------------------------------


def get_port_stats(controller, network_id, port_id):
    try:
        do_single_request("GET", "/ws.v1/lswitch/%s" % (network_id),
                          controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network_id)
    try:
        path = "/ws.v1/lswitch/%s/lport/%s/statistic" % (network_id, port_id)
        resp = do_single_request("GET", path, controller=controller)
        stats = json.loads(resp)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=network_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    LOG.debug("Returning stats for port \"%s\" on \"%s\": %s" % (port_id,
                                                                 network_id,
                                                                 stats))
    return stats


def check_port_state(state):
    if state not in ["ACTIVE", "DOWN"]:
        LOG.error("Invalid port state (ACTIVE and " \
                          "DOWN are valid states): %s" % state)
        raise exception.StateInvalid(port_state=state)


def query_ports(controller, network, relations=None, fields="*", filters=None):
    uri = "/ws.v1/lswitch/" + network + "/lport?"
    if relations:
        uri += "relations=%s" % relations
    uri += "&fields=%s" % fields
    if filters and "attachment" in filters:
        uri += "&attachment_vif_uuid=%s" % filters["attachment"]
    try:
        resp_obj = do_single_request("GET", uri,
          controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return json.loads(resp_obj)["results"]


def delete_port(controller, network, port):
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port
    try:
        do_single_request("DELETE", uri, controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()


def delete_all_ports(controller, ls_uuid):
    res = do_single_request("GET",
      "/ws.v1/lswitch/%s/lport?fields=uuid" % ls_uuid,
      controller=controller)
    res = json.loads(res)
    for r in res["results"]:
        do_single_request("DELETE",
          "/ws.v1/lswitch/%s/lport/%s" % (ls_uuid, r["uuid"]),
          controller=controller)


def get_port(controller, network, port, relations=None):
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "?"
    if relations:
        uri += "relations=%s" % relations
    try:
        resp_obj = do_single_request("GET", uri, controller=controller)
        port = json.loads(resp_obj)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return port


def plug_interface(controller, network, port, type, attachment=None):
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "/attachment"

    lport_obj = {}
    if attachment:
        lport_obj["vif_uuid"] = attachment

    lport_obj["type"] = type
    try:
        resp_obj = do_single_request("PUT", uri,
          json.dumps(lport_obj), controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.Conflict as e:
        LOG.error("Conflict while making attachment to port, " \
                      "Error: %s" % str(e))
        raise exception.AlreadyAttached(att_id=attachment,
                                        port_id=port,
                                        net_id=network,
                                        att_port_id="UNKNOWN")
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    result = json.dumps(resp_obj)
    return result


def unplug_interface(controller, network, port):
    uri = "/ws.v1/lswitch/" + network + "/lport/" + port + "/attachment"
    lport_obj = {"type": "NoAttachment"}
    try:
        resp_obj = do_single_request("PUT",
          uri, json.dumps(lport_obj), controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    return json.loads(resp_obj)


def update_port(network, port_id, **params):
    controller = params["controller"]
    lport_obj = {}

    if "state" in params:
        state = params["state"]
        check_port_state(state)
        admin_status = True
        if state == "DOWN":
            admin_status = False
        lport_obj["admin_status_enabled"] = admin_status

    uri = "/ws.v1/lswitch/" + network + "/lport/" + port_id
    try:
        resp_obj = do_single_request("PUT", uri,
          json.dumps(lport_obj), controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port or Network not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    obj = json.loads(resp_obj)
    obj["port-op-status"] = get_port_status(controller, network, obj["uuid"])
    return obj


def create_port(tenant, network, port_init_state, **params):
    # Check initial state -- this throws an exception if the port state is
    # invalid
    check_port_state(port_init_state)

    controller = params["controller"]

    ls_uuid = network

    admin_status = True
    if port_init_state == "DOWN":
        admin_status = False
    lport_obj = {"admin_status_enabled": admin_status}

    path = "/ws.v1/lswitch/" + ls_uuid + "/lport"
    try:
        resp_obj = do_single_request("POST", path,
          json.dumps(lport_obj), controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=network)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()

    result = json.loads(resp_obj)
    result['port-op-status'] = get_port_status(controller, ls_uuid,
                                               result['uuid'])
    return result


def get_port_status(controller, lswitch_id, port_id):
    """Retrieve the operational status of the port"""
    # Make sure the network exists first
    try:
        do_single_request("GET", "/ws.v1/lswitch/%s" % (lswitch_id),
                          controller=controller)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Network not found, Error: %s" % str(e))
        raise exception.NetworkNotFound(net_id=lswitch_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    try:
        r = do_single_request("GET",
            "/ws.v1/lswitch/%s/lport/%s/status" % (lswitch_id, port_id),
            controller=controller)
        r = json.loads(r)
    except NvpApiClient.ResourceNotFound as e:
        LOG.error("Port not found, Error: %s" % str(e))
        raise exception.PortNotFound(port_id=port_id, net_id=lswitch_id)
    except NvpApiClient.NvpApiException as e:
        raise exception.QuantumException()
    if r['link_status_up'] is True:
        return "UP"
    else:
        return "DOWN"
