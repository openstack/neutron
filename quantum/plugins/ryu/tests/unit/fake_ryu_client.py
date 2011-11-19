# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
# All Rights Reserved.
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


class OFPClient(object):
    def __init__(self, address):
        super(OFPClient, self).__init__()
        self.address = address

    def get_networks(self):
        pass

    def create_network(self, network_id):
        pass

    def update_network(self, network_id):
        pass

    def delete_network(self, network_id):
        pass

    def get_ports(self, network_id):
        pass

    def create_port(self, network_id, dpid, port):
        pass

    def update_port(self, network_id, dpid, port):
        pass

    def delete_port(self, network_id, dpid, port):
        pass
