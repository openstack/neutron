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

import logging as LOG
from optparse import OptionParser
import sys

from quantum.client import Client
from quantum.manager import QuantumManager

FORMAT = "json"
CONTENT_TYPE = "application/" + FORMAT


def delete_all_nets(client):
    res = client.list_networks()
    for n in res["networks"]:
        nid = n["id"]

        pres = client.list_ports(nid)
        for port in pres["ports"]:
            pid = port['id']
            client.detach_resource(nid, pid)
            client.delete_port(nid, pid)
            print "Deleted Virtual Port:%s " \
                "on Virtual Network:%s" % (pid, nid)
        client.delete_network(nid)
        print "Deleted Virtual Network with ID:%s" % nid


def create_net_with_attachments(client, net_name, iface_ids):
        data = {'network': {'net-name': '%s' % net_name}}
        res = client.create_network(data)
        nid = res["networks"]["network"]["id"]
        print "Created a new Virtual Network %s with ID:%s" % (net_name, nid)

        for iface_id in iface_ids:
            res = client.create_port(nid)
            new_port_id = res["ports"]["port"]["id"]
            print "Created Virtual Port:%s " \
                "on Virtual Network:%s" % (new_port_id, nid)
            data = {'port': {'attachment-id': '%s' % iface_id}}
            client.attach_resource(nid, new_port_id, data)
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

    client = Client(options.host, options.port, options.ssl, tenant=tenant_id)

    if options.delete:
        delete_all_nets(client)

    for net_name, iface_ids in nets.items():
        create_net_with_attachments(client, net_name, iface_ids)

    sys.exit(0)
