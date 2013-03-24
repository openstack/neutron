#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless equired by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
#
# @author: Aaron Rosen, VMware

import sys

from oslo.config import cfg

from quantum.common import config
from quantum.plugins.nicira.nicira_nvp_plugin import NvpApiClient
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
from quantum.plugins.nicira.nicira_nvp_plugin import QuantumPlugin

config.setup_logging(cfg.CONF)


def help():
    print "Usage ./check_nvp_config path/to/nvp.ini"
    exit(1)


def display_controller_info(controller):
    print "\tCan login: %s" % controller.get('can_login')
    print "\tuser: %s" % controller.get('user')
    print "\tpassword: %s" % controller.get('password')
    print "\tip: %s" % controller.get('ip')
    print "\tport: %s" % controller.get('port')
    print "\trequested_timeout: %s" % controller.get('requested_timeout')
    print "\tretires: %s" % controller.get('retries')
    print "\tredirects: %s" % controller.get('redirects')
    print "\thttp_timeout: %s" % controller.get('http_timeout')


def test_controller(cluster, controller):
    api_providers = [(controller.get('ip'), controller.get('port'), True)]
    api_client = NvpApiClient.NVPApiHelper(
        api_providers, cluster.user, cluster.password,
        controller.get('requested_timeout'),
        controller.get('http_timeout'),
        controller.get('retries'),
        controller.get('redirects'))

    controller['can_login'] = (api_client.login() and True or False)


def get_gateway_services(cluster):
    ret_gw_services = {"L2GatewayServiceConfig": [],
                       "L3GatewayServiceConfig": []}
    gw_services = nvplib.get_gateway_services(cluster).get('results')
    if gw_services:
        for gw_service in gw_services:
            ret_gw_services[gw_service['type']].append(gw_service['uuid'])

    return ret_gw_services


def get_transport_zones(cluster):
    transport_zones = nvplib.get_transport_zones(cluster).get('results')
    return [transport_zone['uuid'] for transport_zone in transport_zones]


def main(argv):
    if len(sys.argv) != 2:
        help()
    args = ['--config-file']
    args.append(sys.argv[1])
    config.parse(args)
    errors = False
    nvp_opts, clusters_opts = QuantumPlugin.parse_config()
    print "-----------Database Options--------------------"
    print "sql_connection: %s" % cfg.CONF.DATABASE.sql_connection
    print "reconnect_interval: %d" % cfg.CONF.DATABASE.reconnect_interval
    print "sql_max_retries: %d" % cfg.CONF.DATABASE.sql_max_retries
    print "-----------NVP Options--------------------"
    print ("Number of concurrents allow to each controller %d" %
           nvp_opts.concurrent_connections)
    print "NVP Generation Timeout %d" % nvp_opts.nvp_gen_timeout
    print "NVP Default Cluster Name %s" % nvp_opts.default_cluster_name

    print "-----------Cluster Options--------------------"
    if not clusters_opts:
        print "No NVP Clusters detected in nvp.ini!"
        exit(1)
    clusters, default_cluster = QuantumPlugin.parse_clusters_opts(
        clusters_opts, nvp_opts.concurrent_connections,
        nvp_opts.nvp_gen_timeout, nvp_opts.default_cluster_name)
    for cluster in clusters.itervalues():
        num_controllers = cluster.get_num_controllers()
        print "\n%d controllers found in cluster [CLUSTER:%s]" % (
            num_controllers, cluster.name)
        if num_controllers == 0:
            print ("Cluster %s has no nvp_controller_connection defined!" %
                   cluster.name)
            exit(1)

        for i in range(0, num_controllers):
            controller = cluster.get_controller(i)
            if i == 0:
                gateway_services = get_gateway_services(cluster)
                transport_zones = get_transport_zones(cluster)
                controller.update(nvplib.check_cluster_connectivity(cluster))
                default_tz_zone = controller.get('default_tz_uuid')
                print ("\n\tdefault_tz_uuid: %s" % default_tz_zone)
                if not default_tz_zone:
                    print "\t* ERROR: No default trasport zone specified!"
                    errors = True
                elif default_tz_zone not in transport_zones:
                    print ("\t* ERROR: did not find default transport %s zone "
                           "on NVP!" % default_tz_zone)
                    errors = True
                print ("\tapi_redirect_interval: %s" %
                       controller.get('api_redirect_interval'))
                print "\tcluster uuid: %s" % controller.get('uuid')
                print "\tapi_mode: %s" % controller.get('api_mode')
                l2_gateway = controller.get('default_l2_gw_service_uuid')
                print ("\tdefault_l2_gw_service_uuid: %s" % l2_gateway)
                if (l2_gateway and l2_gateway not in
                        gateway_services['L2GatewayServiceConfig']):
                    print ("\t* ERROR: Did not find L2 gateway service uuid %s"
                           " in NVP!" % l2_gateway)
                    errors = True
                l3_gateway = controller.get('default_l3_gw_service_uuid')
                print ("\tdefault_l3_gw_service_uuid: %s" % l3_gateway)
                if (l3_gateway and l3_gateway not in
                        gateway_services['L3GatewayServiceConfig']):
                    print ("\t* ERROR did not find L3 gateway service uuid %s"
                           " in NVP!" % l3_gateway)
                    errors = True
            print ("\n-----controller %d------\n" % (i + 1))
            test_controller(cluster, controller)
            display_controller_info(controller)
        print "\n"
    if errors:
        print ("**There were configuration errors found "
               "please review output carefully!!**")
        print "\n"
