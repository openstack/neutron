
import os
import sys

import gettext

#gettext.install('quantum', unicode=1)
possible_topdir = os.path.normpath(os.path.join(os.path.abspath(sys.argv[0]),
                                   os.pardir,
                                   os.pardir))
if os.path.exists(os.path.join(possible_topdir, 'quantum', '__init__.py')):
    sys.path.insert(0, possible_topdir)

gettext.install('quantum', unicode=1)

from test_scripts.miniclient import MiniClient
from test_client import ExtClient
from quantum.common.wsgi import Serializer

HOST = '127.0.0.1'
PORT = 9696
USE_SSL = False
TENANT_ID = 'ucs_user'


test_network_data = \
    {'network': {'net-name': 'cisco_test_network',
                 'valn-id': 28}}
test_portprofile_data = \
    {'portprofile': {'portprofile_name': 'cisco_test_portprofile',
                 'qos_name': 2,
                 'qos_name': 'test-qos'}}
test_cred_data = \
    {'credential': {'credential_name': 'cred3',
                    'user_name': 'newUser',
                    'password': 'newPasswd'
                    }}
test_qos_data = \
    {'qos': {'qos_name': 'plantimum',
                    'qos_desc': {'PPS': 50, 'TTL': 5}}}


#we put this assignment under portprofile resources
#therefore we need to create such a test data
test_port_assign_data = {'portprofile': {'network-id': '001',
                                         'port-id': '1'}}
test_attach_data = {'port': {'attachment-id': 'v01'}}

test_act_data = {"get_available_host":123}

test_instance_data={'novatenant':{'instance_id' : 1, 
                    'instance_desc' : {'key1' : '1',
                                       'key2' : '2'
                                       }}}

def test_get_host(format='json'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    body = Serializer().serialize(test_instance_data, content_type)
    res = client.do_request(TENANT_ID, 
                            'PUT', "/novatenants/001/get_host." + format, body=body)
    print "XML Response"
    print_response(res)
    print "COMPLETED"
    print "----------------------------"    
    
def test_get_instance_port(format='json'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    body = Serializer().serialize(test_instance_data, content_type)
    res = client.do_request(TENANT_ID, 
                            'PUT', "/novatenants/001/get_instance_port." + format, body=body)
    print "XML Response"
    print_response(res)
    print "COMPLETED"
    print "----------------------------"

def test_action_ext(format='json'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    action_name = 'get_available_host'
    action_params = dict(name='test')
    body = Serializer().serialize(test_act_data, content_type)
 
  
    res = client.do_request(TENANT_ID, 'POST', "/act_resources/1/action." + format, body=body)
    content = print_response(res)

def print_response(res):
    content = res.read()
    print "Status: %s" % res.status
    print "Content: %s" % content
    return content


def create_cisco_network(format='xml'):
    
    client = MiniClient(HOST, PORT, USE_SSL)
    print "CREATE NETWORK -- FORMAT:%s" % format 
    print "----------------------------"
    content_type = "application/" + format
    body = Serializer().serialize(test_network_data, content_type)
    res = client.do_request(TENANT_ID, 
                            'POST', "/networks." + format, body=body)
    print "XML Response"
    print_response(res)
    print "COMPLETED"
    print "----------------------------"


def create_cisco_portprofile(format='xml'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    print "List all Profile -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/portprofiles." + format)
    content = print_response(res)
    portprofile_data = Serializer().deserialize(content, content_type)
    print portprofile_data
  
    print "List a specific Profile -- FORMAT:%s" % format
    profile_id = portprofile_data['portprofiles'][0]['id']
    #profile_id='001'
    print "profile_id " + profile_id
    res = client.do_request(TENANT_ID, 
                            'GET', "/portprofiles/" 
                            + profile_id + "." + format)
    print_response(res)
    
    print "CREATE Profile -- FORMAT:%s" % format
    print "----------------------------"
    content_type = "application/" + format
    body = Serializer().serialize(test_portprofile_data, content_type)
    print "***BODY is "
    print body
    res = client.do_request(TENANT_ID, 'POST', 
                            "/portprofiles." + format, body=body)
    print "XML Response"
    print_response(res)
    print "COMPLETED"
    print "----------------------------"

def test_credential (format='xml'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    print "----------------------------"
    print "List all credentials -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/credentials." + format)
    content = print_response(res)
    credential_data = Serializer().deserialize(content, content_type)
    print credential_data
    
    print "----------------------------"
    print "CREATE Credential -- FORMAT:%s" % format
    print "----------------------------"
    content_type = "application/" + format
    body = Serializer().serialize(test_cred_data, content_type)
    print "***BODY is "
    print body
    res = client.do_request(TENANT_ID, 'POST', 
                            "/credentials." + format, body=body)
    print "XML Response"
    print_response(res)
  
    print "----------------------------"
    print "List all credentials -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/credentials." + format)
    content = print_response(res)
    credential_data = Serializer().deserialize(content, content_type)
    print credential_data
    print "----------------------------"
    print "List a specific cred -- FORMAT:%s" % format
    print "----------------------------"
    cred_id = credential_data['credentials'][0]['id']
    #cred_id='001'
    print "cred_id " + cred_id
    res = client.do_request(TENANT_ID, 
                            'GET', "/credentials/" 
                            + cred_id + "." + format)
    print_response(res)
    
    print "----------------------------"
    print "TEST DELETE Credential -- FORMAT:%s" % format 
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'DELETE',
                            "/credentials/" + cred_id + "." + format)
    print_response(res)
    
    print "----------------------------"
    print "List all credentials -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/credentials." + format)
    content = print_response(res)
    credential_data = Serializer().deserialize(content, content_type)
    print credential_data
    
    print "COMPLETED"
    print "----------------------------"

def test_qos (format='xml'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    print "----------------------------"
    print "List all qoss -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/qoss." + format)
    content = print_response(res)
    qos_data = Serializer().deserialize(content, content_type)
    print qos_data
    
    print "----------------------------"
    print "CREATE qos -- FORMAT:%s" % format
    print "----------------------------"
    content_type = "application/" + format
    body = Serializer().serialize(test_qos_data, content_type)
    print "***BODY is "
    print body
    res = client.do_request(TENANT_ID, 'POST', 
                            "/qoss." + format, body=body)
    print "XML Response"
    print_response(res)
  
    print "----------------------------"
    print "List all qoss -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/qoss." + format)
    content = print_response(res)
    qos_data = Serializer().deserialize(content, content_type)
    print qos_data
    print "----------------------------"
    print "List a specific cred -- FORMAT:%s" % format
    print "----------------------------"
    qos_id = qos_data['qoss'][0]['id']
    #cred_id='001'
    print "qos_id " + qos_id
    res = client.do_request(TENANT_ID, 
                            'GET', "/qoss/" 
                            + qos_id + "." + format)
    print_response(res)
    
    print "----------------------------"
    print "TEST DELETE qos -- FORMAT:%s" % format 
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'DELETE',
                            "/qoss/" + qos_id + "." + format)
    print_response(res)
    
    print "----------------------------"
    print "List all qoss -- FORMat%s" % format
    print "----------------------------"
    res = client.do_request(TENANT_ID, 'GET', "/qoss." + format)
    content = print_response(res)
    qos_data = Serializer().deserialize(content, content_type)
    print qos_data
    
    print "COMPLETED"
    print "----------------------------"

def test_delete_network(format='xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    print "TEST DELETE NETWORK -- FORMAT:%s" % format 
    print "----------------------------"
    print "--> Step 1 - List All Networks"
    res = client.do_request(TENANT_ID, 'GET', "/networks." + format)
    content = print_response(res)
    network_data = Serializer().deserialize(content, content_type)
    print network_data
    net_id = network_data['networks'][0]['id']
    print "--> Step 2 - Delete network %s" % net_id    
    res = client.do_request(TENANT_ID, 'DELETE',
                            "/networks/" + net_id + "." + format)
    print_response(res)
    print "--> Step 3 - List All Networks (Again)"
    res = client.do_request(TENANT_ID, 'GET', "/networks." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"


def test_delete_portprofile(format='xml'):
    client = ExtClient(HOST, PORT, USE_SSL)
    content_type = "application/" + format
    print "TEST DELETE PROFILE -- FORMAT:%s" % format 
    print "----------------------------"
    print "--> Step 1 - List All Profiles"
    res = client.do_request(TENANT_ID, 'GET', "/portprofiles." + format)
    content = print_response(res)
    portprofile_data = Serializer().deserialize(content, content_type)
    print portprofile_data
    profile_id = portprofile_data['portprofiles'][0]['id']
    print "--> Step 2 - Delete portprofile %s" % profile_id    
    res = client.do_request(TENANT_ID, 'DELETE',
                            "/portprofiles/" + profile_id + "." + format)
    print_response(res)
    print "--> Step 3 - List All Profiles (Again)"
    res = client.do_request(TENANT_ID, 'GET', "/portprofiles." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"
 
    
def test_create_port(format='xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    print "TEST CREATE PORT -- FORMAT:%s" % format 
    print "----------------------------"
    print "--> Step 1 - List Ports for network 001"
    res = client.do_request(TENANT_ID, 'GET', "/networks/001/ports." + format)
    print_response(res)
    print "--> Step 2 - Create Port for network 001"
    res = client.do_request(TENANT_ID, 'POST', "/networks/001/ports." + format)
    print_response(res)
    print "--> Step 3 - List Ports for network 001 (again)"
    res = client.do_request(TENANT_ID, 'GET', "/networks/001/ports." + format)
    print_response(res)
    print "COMPLETED"
    print "----------------------------"


#assuming network 001 and ports 1 are created in the plug-in    
def test_attach_resource(format='xml'):
    client = MiniClient(HOST, PORT, USE_SSL)
    print "TEST attach resources to port"
    content_type = "application/" + format
    body = Serializer().serialize(test_attach_data, content_type)
    #attach virtual interface to the port
    res = client.do_request(TENANT_ID, 'PUT', 
                            "/networks/001/ports/1/attachment." 
                            + format, body=body)
    print_response(res)
    #list existing interface of the port
    res = client.do_request(TENANT_ID, 'GET', 
                            "/networks/001/ports/1/attachment." + format)
    print_response(res)
    #de_attach virtual interface from the port
    res = client.do_request(TENANT_ID, 'DELETE', 
                            "/networks/001/ports/1/attachment." + format)
    print_response(res)
    #list existing interface of the port
    res = client.do_request(TENANT_ID, 'GET', 
                            "/networks/001/ports/1/attachment." + format)
    print_response(res)


#assuming network 001, ports 1 and portprofile 002 are created in the plug-in 
def test_assign_portprofile(format='xml'):
    client = ExtClient(HOST, PORT, USE_SSL)
    print "TEST attach resources to port"
    content_type = "application/" + format
    body = Serializer().serialize(test_port_assign_data, content_type)
    print "body is " + body
    res = client.do_request(TENANT_ID, 'PUT', 
                            "/portprofiles/001/associate_portprofile." 
                            + format, body=body)
    print_response(res)
    res = client.do_request(TENANT_ID, 'POST', 
                            "/portprofiles/001/disassociate_portprofile." 
                            + format, body=body)
   
    print_response(res)
    
    
def main():
    create_cisco_portprofile('json') 
    test_attach_resource('json') 
   
    test_delete_portprofile('json') 
    test_credential('json')
    test_qos('json')
    ##test_action_ext('json')
    test_get_host('json')
    test_get_instance_port('json')
    
    #create_cisco_network('json')
    #test_create_port('json')
    #create_cisco_portprofile('json')
    #test_assign_portprofile('json')
    pass
    

# Standard boilerplate to call the main() function.
if __name__ == '__main__':
    main()
