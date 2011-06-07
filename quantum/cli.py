# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011, Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.

import sys

from manager import QuantumManager


def usage():
    print "\nUsage:"
    print "list_nets <tenant-id>"
    print "create_net <tenant-id> <net-name>"
    print "delete_net <tenant-id> <net-id>"
    print "detail_net <tenant-id> <net-id>"
    print "rename_net <tenant-id> <net-id> <new name>"
    print "list_ports <tenant-id> <net-id>"
    print "create_port <tenant-id> <net-id>"
    print "delete_port <tenant-id> <net-id> <port-id>"
    print "detail_port <tenant-id> <net-id> <port-id>"
    print "plug_iface <tenant-id> <net-id> <port-id> <iface-id>"
    print "unplug_iface <tenant-id> <net-id> <port-id>"
    print "detail_iface <tenant-id> <net-id> <port-id>"
    print "list_iface <tenant-id> <net-id>\n"

if len(sys.argv) < 2 or len(sys.argv) > 6:
    usage()
    exit(1)

quantum = QuantumManager()
manager = quantum.get_manager()

if sys.argv[1] == "list_nets" and len(sys.argv) == 3:
    network_on_tenant = manager.get_all_networks(sys.argv[2])
    print "Virtual Networks on Tenant:%s\n" % sys.argv[2]
    for k, v in network_on_tenant.iteritems():
        print"\tNetwork ID:%s \n\tNetwork Name:%s \n" % (k, v)
elif sys.argv[1] == "create_net" and len(sys.argv) == 4:
    new_net_id = manager.create_network(sys.argv[2], sys.argv[3])
    print "Created a new Virtual Network with ID:%s\n" % new_net_id
elif sys.argv[1] == "delete_net" and len(sys.argv) == 4:
    manager.delete_network(sys.argv[2], sys.argv[3])
    print "Deleted Virtual Network with ID:%s" % sys.argv[3]
elif sys.argv[1] == "detail_net" and len(sys.argv) == 4:
    vif_list = manager.get_network_details(sys.argv[2], sys.argv[3])
    print "Remote Interfaces on Virtual Network:%s\n" % sys.argv[3]
    for iface in vif_list:
        print "\tRemote interface :%s" % iface
elif sys.argv[1] == "rename_net" and len(sys.argv) == 5:
    manager.rename_network(sys.argv[2], sys.argv[3], sys.argv[4])
    print "Renamed Virtual Network with ID:%s" % sys.argv[3]
elif sys.argv[1] == "list_ports" and len(sys.argv) == 4:
    ports = manager.get_all_ports(sys.argv[2], sys.argv[3])
    print " Virtual Ports on Virtual Network:%s\n" % sys.argv[3]
    for port in ports:
        print "\tVirtual Port:%s" % port
elif sys.argv[1] == "create_port" and len(sys.argv) == 4:
    new_port = manager.create_port(sys.argv[2], sys.argv[3])
    print "Created Virtual Port:%s " \
          "on Virtual Network:%s" % (new_port, sys.argv[3])
elif sys.argv[1] == "delete_port" and len(sys.argv) == 5:
    manager.delete_port(sys.argv[2], sys.argv[3], sys.argv[4])
    print "Deleted Virtual Port:%s " \
          "on Virtual Network:%s" % (sys.argv[3], sys.argv[4])
elif sys.argv[1] == "detail_port" and len(sys.argv) == 5:
    port_detail = manager.get_port_details(sys.argv[2],
                                           sys.argv[3], sys.argv[4])
    print "Virtual Port:%s on Virtual Network:%s " \
          "contains remote interface:%s" % (sys.argv[3],
                                            sys.argv[4],
                                            port_detail)
elif sys.argv[1] == "plug_iface" and len(sys.argv) == 6:
    manager.plug_interface(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    print "Plugged remote interface:%s " \
          "into Virtual Network:%s" % (sys.argv[5], sys.argv[3])
elif sys.argv[1] == "unplug_iface" and len(sys.argv) == 5:
    manager.unplug_interface(sys.argv[2], sys.argv[3], sys.argv[4])
    print "UnPlugged remote interface " \
          "from Virtual Port:%s Virtual Network:%s" % (sys.argv[4],
                                                       sys.argv[3])
elif sys.argv[1] == "detail_iface" and len(sys.argv) == 5:
    remote_iface = manager.get_interface_details(sys.argv[2],
                                                 sys.argv[3], sys.argv[4])
    print "Remote interface on Virtual Port:%s " \
          "Virtual Network:%s is %s" % (sys.argv[4],
                                        sys.argv[3], remote_iface)
elif sys.argv[1] == "list_iface" and len(sys.argv) == 4:
    iface_list = manager.get_all_attached_interfaces(sys.argv[2], sys.argv[3])
    print "Remote Interfaces on Virtual Network:%s\n" % sys.argv[3]
    for iface in iface_list:
        print "\tRemote interface :%s" % iface
elif sys.argv[1] == "all" and len(sys.argv) == 2:
    print "Not Implemented"
else:
    print "invalid arguments: %s" % str(sys.argv)
    usage()
