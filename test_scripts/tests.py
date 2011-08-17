# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Citrix Systems
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

import gettext

gettext.install('quantum', unicode=1)

from miniclient import MiniClient
from quantum.common.wsgi import Serializer

HOST = '127.0.0.1'
PORT = 9696
USE_SSL = False
TENANT_ID = 'totore'

test_network_data = \
    {'network': {'network-name': 'test' }}

def print_response(res):
    content = res.read()
    print "Status: %s" %res.status
    print "Content: %s" %content
    return content

def test_list_networks_and_ports(format = 'xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    print "TEST LIST NETWORKS AND PORTS -- FORMAT:%s" %format 
    print "----------------------------"
    print "--> Step 1 - List All Networks"
    res = client.do_request(TENANT_ID,'GET', "/networks." + format)
    print_response(res)
    print "--> Step 2 - Details for Network 001"
    res = client.do_request(TENANT_ID,'GET', "/networks/001." + format)
    print_response(res)
    print "--> Step 3 - Ports for Network 001"
    res = client.do_request(TENANT_ID,'GET', "/networks/001/ports." + format)
    print_response(res)
    print "--> Step 4 - Details for Port 1"
    res = client.do_request(TENANT_ID,'GET', "/networks/001/ports/1." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"
    
def test_create_network(format = 'xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    print "TEST CREATE NETWORK -- FORMAT:%s" %format 
    print "----------------------------"
    print "--> Step 1 - Create Network"
    content_type = "application/" + format
    body = Serializer().serialize(test_network_data, content_type)
    res = client.do_request(TENANT_ID,'POST', "/networks." + format, body=body)
    print_response(res)
    print "--> Step 2 - List All Networks"
    res = client.do_request(TENANT_ID,'GET', "/networks." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"

def test_rename_network(format = 'xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format    
    print "TEST RENAME NETWORK -- FORMAT:%s" %format 
    print "----------------------------"
    print "--> Step 1 - Retrieve network"
    res = client.do_request(TENANT_ID,'GET', "/networks/001." + format)
    print_response(res)
    print "--> Step 2 - Rename network to 'test_renamed'"
    test_network_data['network']['network-name'] = 'test_renamed'
    body = Serializer().serialize(test_network_data, content_type)
    res = client.do_request(TENANT_ID,'PUT', "/networks/001." + format, body=body)
    print_response(res)
    print "--> Step 2 - Retrieve network (again)"
    res = client.do_request(TENANT_ID,'GET', "/networks/001." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"
    
def test_delete_network(format = 'xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    print "TEST DELETE NETWORK -- FORMAT:%s" %format 
    print "----------------------------"
    print "--> Step 1 - List All Networks"
    res = client.do_request(TENANT_ID,'GET', "/networks." + format)
    content = print_response(res)
    network_data = Serializer().deserialize(content, content_type)
    print network_data
    net_id = network_data['networks'][0]['id']
    print "--> Step 2 - Delete network %s" %net_id    
    res = client.do_request(TENANT_ID,'DELETE',
                            "/networks/" + net_id + "." + format)
    print_response(res)
    print "--> Step 3 - List All Networks (Again)"
    res = client.do_request(TENANT_ID,'GET', "/networks." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"


def test_create_port(format = 'xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    print "TEST CREATE PORT -- FORMAT:%s" %format 
    print "----------------------------"
    print "--> Step 1 - List Ports for network 001"
    res = client.do_request(TENANT_ID,'GET', "/networks/001/ports." + format)
    print_response(res)
    print "--> Step 2 - Create Port for network 001"
    res = client.do_request(TENANT_ID,'POST', "/networks/001/ports." + format)
    print_response(res)
    print "--> Step 3 - List Ports for network 001 (again)"
    res = client.do_request(TENANT_ID,'GET', "/networks/001/ports." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"


def main():
    test_list_networks_and_ports('xml')
    test_list_networks_and_ports('json')
    test_create_network('xml')
    test_create_network('json')
    test_rename_network('xml')
    test_rename_network('json')
    # NOTE: XML deserializer does not work properly 
    # disabling XML test - this is NOT a server-side issue
    #test_delete_network('xml')
    test_delete_network('json')
    test_create_port('xml')
    test_create_port('json')
    
    pass
    

# Standard boilerplate to call the main() function.
if __name__ == '__main__':
    main()