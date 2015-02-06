# Copyright 2013 VMware, Inc.
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

from __future__ import print_function

import sys

from oslo_config import cfg

from neutron.common import config
from neutron.plugins.vmware.common import config as nsx_config  # noqa
from neutron.plugins.vmware.common import nsx_utils
from neutron.plugins.vmware import nsxlib

config.setup_logging()


def help(name):
    print("Usage: %s path/to/neutron/plugin/ini/config/file" % name)
    sys.exit(1)


def get_nsx_controllers(cluster):
    return cluster.nsx_controllers


def config_helper(config_entity, cluster):
    try:
        return nsxlib.do_request('GET',
                                 "/ws.v1/%s?fields=uuid" % config_entity,
                                 cluster=cluster).get('results', [])
    except Exception as e:
        msg = (_("Error '%(err)s' when connecting to controller(s): %(ctl)s.")
               % {'err': e,
                  'ctl': ', '.join(get_nsx_controllers(cluster))})
        raise Exception(msg)


def get_control_cluster_nodes(cluster):
    return config_helper("control-cluster/node", cluster)


def get_gateway_services(cluster):
    ret_gw_services = {"L2GatewayServiceConfig": [],
                       "L3GatewayServiceConfig": []}
    gw_services = config_helper("gateway-service", cluster)
    for gw_service in gw_services:
        ret_gw_services[gw_service['type']].append(gw_service['uuid'])
    return ret_gw_services


def get_transport_zones(cluster):
    transport_zones = config_helper("transport-zone", cluster)
    return [transport_zone['uuid'] for transport_zone in transport_zones]


def get_transport_nodes(cluster):
    transport_nodes = config_helper("transport-node", cluster)
    return [transport_node['uuid'] for transport_node in transport_nodes]


def is_transport_node_connected(cluster, node_uuid):
    try:
        return nsxlib.do_request('GET',
                                 "/ws.v1/transport-node/%s/status" % node_uuid,
                                 cluster=cluster)['connection']['connected']
    except Exception as e:
        msg = (_("Error '%(err)s' when connecting to controller(s): %(ctl)s.")
               % {'err': e,
                  'ctl': ', '.join(get_nsx_controllers(cluster))})
        raise Exception(msg)


def main():
    if len(sys.argv) != 2:
        help(sys.argv[0])
    args = ['--config-file']
    args.append(sys.argv[1])
    config.init(args)
    print("----------------------- Database Options -----------------------")
    print("\tconnection: %s" % cfg.CONF.database.connection)
    print("\tretry_interval: %d" % cfg.CONF.database.retry_interval)
    print("\tmax_retries: %d" % cfg.CONF.database.max_retries)
    print("-----------------------    NSX Options   -----------------------")
    print("\tNSX Generation Timeout %d" % cfg.CONF.NSX.nsx_gen_timeout)
    print("\tNumber of concurrent connections to each controller %d" %
          cfg.CONF.NSX.concurrent_connections)
    print("\tmax_lp_per_bridged_ls: %s" % cfg.CONF.NSX.max_lp_per_bridged_ls)
    print("\tmax_lp_per_overlay_ls: %s" % cfg.CONF.NSX.max_lp_per_overlay_ls)
    print("-----------------------  Cluster Options -----------------------")
    print("\tretries: %s" % cfg.CONF.retries)
    print("\tredirects: %s" % cfg.CONF.redirects)
    print("\thttp_timeout: %s" % cfg.CONF.http_timeout)
    cluster = nsx_utils.create_nsx_cluster(
        cfg.CONF,
        cfg.CONF.NSX.concurrent_connections,
        cfg.CONF.NSX.nsx_gen_timeout)
    nsx_controllers = get_nsx_controllers(cluster)
    num_controllers = len(nsx_controllers)
    print("Number of controllers found: %s" % num_controllers)
    if num_controllers == 0:
        print("You must specify at least one controller!")
        sys.exit(1)

    get_control_cluster_nodes(cluster)
    for controller in nsx_controllers:
        print("\tController endpoint: %s" % controller)
        gateway_services = get_gateway_services(cluster)
        default_gateways = {
            "L2GatewayServiceConfig": cfg.CONF.default_l2_gw_service_uuid,
            "L3GatewayServiceConfig": cfg.CONF.default_l3_gw_service_uuid}
        errors = 0
        for svc_type in default_gateways.keys():
            for uuid in gateway_services[svc_type]:
                print("\t\tGateway(%s) uuid: %s" % (svc_type, uuid))
            if (default_gateways[svc_type] and
                default_gateways[svc_type] not in gateway_services[svc_type]):
                print("\t\t\tError: specified default %s gateway (%s) is "
                      "missing from NSX Gateway Services!" % (
                          svc_type,
                          default_gateways[svc_type]))
                errors += 1
        transport_zones = get_transport_zones(cluster)
        print("\tTransport zones: %s" % transport_zones)
        if cfg.CONF.default_tz_uuid not in transport_zones:
            print("\t\tError: specified default transport zone "
                  "(%s) is missing from NSX transport zones!"
                  % cfg.CONF.default_tz_uuid)
            errors += 1
        transport_nodes = get_transport_nodes(cluster)
        print("\tTransport nodes: %s" % transport_nodes)
        node_errors = []
        for node in transport_nodes:
            if not is_transport_node_connected(cluster, node):
                node_errors.append(node)

    # Use different exit codes, so that we can distinguish
    # between config and runtime errors
    if len(node_errors):
        print("\nThere are one or mode transport nodes that are "
              "not connected: %s. Please, revise!" % node_errors)
        sys.exit(10)
    elif errors:
        print("\nThere are %d errors with your configuration. "
              "Please, revise!" % errors)
        sys.exit(12)
    else:
        print("Done.")
