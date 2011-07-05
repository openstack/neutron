# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc.
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
# @author: Dan Wendlandt, Nicira Networks, Inc.

import httplib
import logging as LOG
import json
import socket
import sys
import urllib

from quantum.manager import QuantumManager
from optparse import OptionParser
from quantum.common.wsgi import Serializer
from quantum.cli import MiniClient

FORMAT = "json"
CONTENT_TYPE = "application/" + FORMAT


def delete_all_nets(client, tenant_id):
    res = client.do_request(tenant_id, 'GET', "/networks." + FORMAT)
    resdict = json.loads(res.read())
    LOG.debug(resdict)
    for n in resdict["networks"]:
        nid = n["id"]

        res = client.do_request(tenant_id, 'GET',
            "/networks/%s/ports.%s" % (nid, FORMAT))
        output = res.read()
        if res.status != 200:
            LOG.error("Failed to list ports: %s" % output)
            continue
        rd = json.loads(output)
        LOG.debug(rd)
        for port in rd["ports"]:
            pid = port["id"]

            data = {'port': {'attachment-id': ''}}
            body = Serializer().serialize(data, CONTENT_TYPE)
            res = client.do_request(tenant_id, 'DELETE',
                "/networks/%s/ports/%s/attachment.%s" % \
                (nid, pid, FORMAT), body=body)
            output = res.read()
            LOG.debug(output)
            if res.status != 202:
                LOG.error("Failed to unplug iface from port \"%s\": %s" % (vid,
                pid, output))
                continue
            LOG.info("Unplugged interface from port:%s on network:%s" % (pid,
                                                                        nid))

            res = client.do_request(tenant_id, 'DELETE',
                "/networks/%s/ports/%s.%s" % (nid, pid, FORMAT))
            output = res.read()
            if res.status != 202:
                LOG.error("Failed to delete port: %s" % output)
                continue
            print "Deleted Virtual Port:%s " \
                "on Virtual Network:%s" % (pid, nid)

        res = client.do_request(tenant_id, 'DELETE',
                    "/networks/" + nid + "." + FORMAT)
        status = res.status
        if status != 202:
            Log.error("Failed to delete network: %s" % nid)
            output = res.read()
            print output
        else:
            print "Deleted Virtual Network with ID:%s" % nid


def create_net_with_attachments(net_name, iface_ids):
        data = {'network': {'network-name': '%s' % net_name}}
        body = Serializer().serialize(data, CONTENT_TYPE)
        res = client.do_request(tenant_id, 'POST',
            "/networks." + FORMAT, body=body)
        rd = json.loads(res.read())
        LOG.debug(rd)
        nid = rd["networks"]["network"]["id"]
        print "Created a new Virtual Network %s with ID:%s" % (net_name, nid)

        for iface_id in iface_ids:
            res = client.do_request(tenant_id, 'POST',
                "/networks/%s/ports.%s" % (nid, FORMAT))
            output = res.read()
            if res.status != 200:
                LOG.error("Failed to create port: %s" % output)
                continue
            rd = json.loads(output)
            new_port_id = rd["ports"]["port"]["id"]
            print "Created Virtual Port:%s " \
                "on Virtual Network:%s" % (new_port_id, nid)
            data = {'port': {'attachment-id': '%s' % iface_id}}
            body = Serializer().serialize(data, CONTENT_TYPE)
            res = client.do_request(tenant_id, 'PUT',
                "/networks/%s/ports/%s/attachment.%s" %\
                 (nid, new_port_id, FORMAT), body=body)
            output = res.read()
            LOG.debug(output)
            if res.status != 202:
                LOG.error("Failed to plug iface \"%s\" to port \"%s\": %s" % \
                        (iface_id, new_port_id, output))
                continue
            print "Plugged interface \"%s\" to port:%s on network:%s" % \
                        (iface_id, new_port_id, nid)

if __name__ == "__main__":
    usagestr = "Usage: %prog [OPTIONS] <tenant-id> <config-string> [args]\n" \
                "Example config-string: net1=instance-1,instance-2"\
                ":net2=instance-3,instance-4\n" \
                "This string would create two networks: \n" \
                "'net1' would have two ports, with iface-ids "\
                "instance-1 and instance-2 attached\n" \
                "'net2' would have two ports, with iface-ids"\
                " instance-3 and instance-4 attached\n"
    parser = OptionParser(usage=usagestr)
    parser.add_option("-H", "--host", dest="host",
      type="string", default="127.0.0.1", help="ip address of api host")
    parser.add_option("-p", "--port", dest="port",
      type="int", default=9696, help="api poort")
    parser.add_option("-s", "--ssl", dest="ssl",
      action="store_true", default=False, help="use ssl")
    parser.add_option("-v", "--verbose", dest="verbose",
      action="store_true", default=False, help="turn on verbose logging")
    parser.add_option("-d", "--delete", dest="delete",
      action="store_true", default=False, \
        help="delete existing tenants networks")

    options, args = parser.parse_args()

    if options.verbose:
        LOG.basicConfig(level=LOG.DEBUG)
    else:
        LOG.basicConfig(level=LOG.WARN)

    if len(args) < 1:
        parser.print_help()
        help()
        sys.exit(1)

    nets = {}
    tenant_id = args[0]
    if len(args) > 1:
        config_str = args[1]
        for net_str in config_str.split(":"):
            arr = net_str.split("=")
            net_name = arr[0]
            nets[net_name] = arr[1].split(",")

    print "nets: %s" % str(nets)

    client = MiniClient(options.host, options.port, options.ssl)

    if options.delete:
        delete_all_nets(client, tenant_id)

    for net_name, iface_ids in nets.items():
        create_net_with_attachments(net_name, iface_ids)

    sys.exit(0)
