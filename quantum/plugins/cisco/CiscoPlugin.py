from quantum.common import exceptions as exc
from extensions import _exceptions as extexc

          
class CiscoPaloPlugin2(object):
    """
    This plugin has internal data structure
    derived from quantum fakeplugin
    """

    #static data for networks and ports
    _port_dict_1 = {
                   1: {'port-id': 1, 
                        'port-state': 'DOWN',
                        'attachment': None,
                        'portprofile': None},
                   2: {'port-id': 2, 
                        'port-state': 'UP',
                        'attachment': None,
                        'portprofile': None}}
    _port_dict_2 = {
                   1: {'port-id': 1, 
                        'port-state': 'UP',
                        'attachment': 'SomeFormOfVIFID',
                        'portprofile': '001'},
                   2: {'port-id': 2, 
                        'port-state': 'DOWN',
                        'attachment': None,
                        'portprofile': '001'}}        
    _networks = {'001':
                    {
                    'net-id': '001',
                    'net-name': 'pippotest',
                    'net-ports': _port_dict_1},
                    '002':
                    {
                    'net-id': '002',
                    'net-name': 'cicciotest',
                    'net-ports': _port_dict_2}}
    _portprofiles = {'001':
                    {
                    'profile_id': '001',
                    'profile_name': 'pprofiletest',
                    'assignment': ['1', '2'],
                    'qos_name': '001'},
                    '002':
                    {
                    'profile_id': '002',
                    'profile_name': 'cicciotest',
                    'qos_name': '002',
                    'assignment': None}}
    
    _credentials = {'001':
                    {
                    'credential_id': '001',
                    'credential_name': 'cred1',
                    'user_name': 'ying',
                    'password': 'yingTest'},
                    '002':
                    {
                    'credential_id': '002',
                    'credential_name': 'cred2',
                    'user_name': 'admin',
                    'password': 'adminTest'}}
    _qoss = {'001':
                    {
                    'qos_id': '001',
                    'qos_name': 'silver',
                    'qos_desc': {'pps':170, 'TTL':20}},
                    '002':
                    {
                    'qos_id': '002',
                    'qos_name': 'gold',
                    'qos_desc': {'pps':340, 'TTL':10}}}
    
    _host = {'host_list': {
                           "host_key1": "host_value1",
                           "host_key2": "host_value2"}}
    _vif = {'vif_desc': {
                           "vif_key1": "vif_value1",
                           "vif_key2": "vif_value2"}
            }
                    
    
    supported_extension_aliases = ["Cisco Credential", "Cisco Port Profile", "Cisco qos", "Cisco Nova Tenant"]
    
    
    """
    def supports_extension(self, extension):
        #return extension.get_alias() == "Cisco Port Profile"
        return extension.get_alias() == "Cisco Credential"
    """
    def __init__(self):
        CiscoPaloPlugin2._net_counter = \
        len(CiscoPaloPlugin2._networks)
        
        CiscoPaloPlugin2._profile_counter = \
        len(CiscoPaloPlugin2._portprofiles)
        
        CiscoPaloPlugin2._credential_counter = \
        len(CiscoPaloPlugin2._credentials)
        
        CiscoPaloPlugin2._qos_counter = \
        len(CiscoPaloPlugin2._qoss)
    def _get_network(self, tenant_id, network_id):
        
        network = CiscoPaloPlugin2._networks.get(network_id)
        if not network:
            raise exc.NetworkNotFound(net_id=network_id)
        return network
    
   
    
    def _get_credential(self, tenant_id, credential_id):
        credential = CiscoPaloPlugin2._credentials.get(credential_id)
        if not credential:
            raise extexc.CredentialNotFound(credential_id=credential_id)
        return credential  
    
    def _get_qos(self, tenant_id, qos_id):
        qos = CiscoPaloPlugin2._qoss.get(qos_id)
        if not qos:
            raise extexc.QosNotFound(qos_id=qos_id)
        return qos  
    
    def _get_port(self, tenant_id, network_id, port_id):
        net = self._get_network(tenant_id, network_id)
        port = net['net-ports'].get(int(port_id))
        if not port:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        return port
    
    def _validate_port_state(self, port_state):
        if port_state.upper() not in ('UP', 'DOWN'):
            raise exc.StateInvalid(port_state=port_state)
        return True
    
    def _validate_attachment(self, tenant_id, network_id, port_id,
                             remote_interface_id):
        network = self._get_network(tenant_id, network_id)
        for port in network['net-ports'].values():
            if port['attachment'] == remote_interface_id:
                raise exc.AlreadyAttached(net_id=network_id,
                                          port_id=port_id,
                                          att_id=port['attachment'],
                                          att_port_id=port['port-id'])
        
    def get_all_networks(self, tenant_id):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant. 
        """
        print("get_all_networks() called\n")
        return CiscoPaloPlugin2._networks.values()

    def get_network_details(self, tenant_id, net_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the network
        """
        print("get_network_details() called\n")
        return self._get_network(tenant_id, net_id)

    def create_network(self, tenant_id, net_name):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        print("create_network() called\n")
        CiscoPaloPlugin2._net_counter += 1
        new_net_id = ("0" * (3 - len(str(CiscoPaloPlugin2._net_counter)))) + \
                    str(CiscoPaloPlugin2._net_counter)
        print new_net_id
        new_net_dict = {'net-id': new_net_id,
                      'net-name': net_name,
                      'net-ports': {}}
        CiscoPaloPlugin2._networks[new_net_id] = new_net_dict
        # return network_id of the created network
        return new_net_dict
    
    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        print("delete_network() called\n")
        net = CiscoPaloPlugin2._networks.get(net_id)
        # Verify that no attachments are plugged into the network
        if net:
            if net['net-ports']:
                for port in net['net-ports'].values():
                    if port['attachment']:
                        raise exc.NetworkInUse(net_id=net_id)
            CiscoPaloPlugin2._networks.pop(net_id)
            return net
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)
    
    def rename_network(self, tenant_id, net_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual Network.
        """
        print("rename_network() called\n")
        net = self._get_network(tenant_id, net_id)
        net['net-name'] = new_name 
        return net

    def _get_portprofile(self, tenant_id, portprofile_id):
        portprofile = CiscoPaloPlugin2._portprofiles.get(portprofile_id)
        if not portprofile:
            raise extexc.PortprofileNotFound(portprofile_id=portprofile_id)
        return portprofile  
    
    def get_all_portprofiles(self, tenant_id):
        """
        Returns a dictionary containing all
        <portprofile_uuid, portprofile_name> for
        the specified tenant. 
        """
        print("get_all_portprofiles() called\n")
        return CiscoPaloPlugin2._portprofiles.values()

    def get_portprofile_details(self, tenant_id, profile_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the portprofile
        """
        print("get_portprofile_details() called\n")
        return self._get_portprofile(tenant_id, profile_id)

    def create_portprofile(self, tenant_id, profile_name, vlan_id):
        """
        Creates a new Virtual portprofile, and assigns it
        a symbolic name.
        """
        print("create_portprofile() called\n")
        CiscoPaloPlugin2._profile_counter += 1
        new_profile_id = ("0" * \
                          (3 - \
                           len(str(CiscoPaloPlugin2._profile_counter)))) + \
                    str(CiscoPaloPlugin2._profile_counter)
        print new_profile_id
        new_profile_dict = {'profile_id': new_profile_id,
                      'profile_name': profile_name,
                      'qos_name': vlan_id,
                      'assignment': None}
        CiscoPaloPlugin2._portprofiles[new_profile_id] = new_profile_dict
        # return portprofile_id of the created portprofile
        return new_profile_dict
    
    def delete_portprofile(self, tenant_id, profile_id):
        """
        Deletes the portprofile with the specified portprofile identifier
        belonging to the specified tenant.
        """
        print("delete_portprofile() called\n")
        profile = CiscoPaloPlugin2._portprofiles.get(profile_id)
        # Verify that no attachments are plugged into the portprofile
        if profile:
            CiscoPaloPlugin2._portprofiles.pop(profile_id)
            return profile
        # portprofile not found
        raise extexc.PortprofileNotFound(profile_id=profile_id)
    
    def rename_portprofile(self, tenant_id, profile_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual portprofile.
        """
        print("rename_portprofile() called\n")
        profile = self._get_portprofile(tenant_id, profile_id)
        profile['profile_name'] = new_name 
        return profile
    
    

    def associate_portprofile(self, tenant_id, net_id, port_id, pprofile_id):
        """
        Assign portprofile to the specified port on the
        specified Virtual Network.
        """
        print("assign_portprofile() called\n")
        print("net_id " + net_id)
        # Validate attachment
        #self._validate_attachment(tenant_id, net_id, port_id,
                               #  remote_interface_id)
        #TODO: modify the exception
        port = self._get_port(tenant_id, net_id, port_id)
        if (not port['portprofile'] == None):
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['portprofile'])
        port['portprofile'] = pprofile_id
    
    def disassociate_portprofile(self, tenant_id, net_id, port_id, portprofile_id):
        """
        De-assign a portprofile from the specified port on the
        specified Virtual Network.
        """
        print("deassign_portprofile() called\n")
        #print("*******net_id is "+net_id)
        port = self._get_port(tenant_id, net_id, port_id)
      
        port['portprofile'] = None
        #TODO:
        #modify assignment[portprofile_id] to remove this port
    
    #TODO: add new data structure to 
    #hold all the assignment for a specific portprofile    
    def get_portprofile_assignment(self, tenant_id, net_id, port_id):
        print("get portprofile assignment called\n") 
        port = self._get_port(tenant_id, net_id, port_id)
        ppid = port['portprofile'] 
        if (ppid == None):
            print("***no portprofile attached")
            return "no portprofile attached"
        else:
            print("***attached portprofile id is " + ppid)
            return ("attached portprofile " + ppid)
        
    
    def get_all_credentials(self, tenant_id):
        """
        Returns a dictionary containing all
        <credential_id, credential_name> for
        the specified tenant. 
        """
        print("get_all_credentials() called\n")
        return CiscoPaloPlugin2._credentials.values()

    def get_credential_details(self, tenant_id, credential_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the credential
        """
        print("get_credential_details() called\n")
        return self._get_credential(tenant_id, credential_id)

    def create_credential(self, tenant_id, credential_name, user_name, password):
        """
        Creates a new Virtual credential, and assigns it
        a symbolic name.
        """
        print("create_credential() called\n")
        CiscoPaloPlugin2._credential_counter += 1
        new_credential_id = ("0" * \
                          (3 - \
                           len(str(CiscoPaloPlugin2._credential_counter)))) + \
                    str(CiscoPaloPlugin2._credential_counter)
        print new_credential_id
        new_credential_dict = {'credential_id': new_credential_id,
                      'credential_name': credential_name,
                      'user_name': user_name,
                      'password': password}
        CiscoPaloPlugin2._credentials[new_credential_id] = new_credential_dict
        # return credential_id of the created credential
        return new_credential_dict
    
    def delete_credential(self, tenant_id, credential_id):
        """
        Deletes the credential with the specified credential identifier
        belonging to the specified tenant.
        """
        print("delete_credential() called\n")
        credential = CiscoPaloPlugin2._credentials.get(credential_id)
        
        if credential:
            CiscoPaloPlugin2._credentials.pop(credential_id)
            return credential
        # credential not found
        raise extexc.CredentialNotFound(credential_id=credential_id)
    
    def rename_credential(self, tenant_id, credential_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual credential.
        """
        print("rename_credential() called\n")
        credential = self._get_credential(tenant_id, credential_id)
        credential['credential_name'] = new_name 
        return credential
    
    
    def get_all_qoss(self, tenant_id):
        """
        Returns a dictionary containing all
        <qos_id, qos_name> for
        the specified tenant. 
        """
        print("get_all_qoss() called\n")
        return CiscoPaloPlugin2._qoss.values()

    def get_qos_details(self, tenant_id, qos_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the qos
        """
        print("get_qos_details() called\n")
        return self._get_qos(tenant_id, qos_id)

    def create_qos(self, tenant_id, qos_name, qos_desc):
        """
        Creates a new Virtual qos, and assigns it
        a symbolic name.
        """
        print("create_qos() called\n")
        CiscoPaloPlugin2._qos_counter += 1
        new_qos_id = ("0" * \
                          (3 - \
                           len(str(CiscoPaloPlugin2._qos_counter)))) + \
                    str(CiscoPaloPlugin2._qos_counter)
        print new_qos_id
        new_qos_dict = {'qos_id': new_qos_id,
                      'qos_name': qos_name,
                      'qos_desc': qos_desc}
        
        print("************************")
        print("test dictionary data")
        print(qos_desc['TTL'])
        print("************************")

        CiscoPaloPlugin2._qoss[new_qos_id] = new_qos_dict
        # return qos_id of the created qos
        return new_qos_dict
    
    def delete_qos(self, tenant_id, qos_id):
        """
        Deletes the qos with the specified qos identifier
        belonging to the specified tenant.
        """
        print("delete_qos() called\n")
        qos = CiscoPaloPlugin2._qoss.get(qos_id)
        # Verify that no attachments are plugged into the qos
        if qos:
            CiscoPaloPlugin2._qoss.pop(qos_id)
            return qos
        # qos not found
        raise extexc.QosNotFound(qos_id=qos_id)
    
    def rename_qos(self, tenant_id, qos_id, new_name):
        """
        Updates the symbolic name belonging to a particular
        Virtual qos.
        """
        print("rename_qos() called\n")
        qos = self._get_qos(tenant_id, qos_id)
        qos['qos_name'] = new_name 
        return qos
    
    
        

    def get_all_ports(self, tenant_id, net_id):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        print("get_all_ports() called\n")
        network = self._get_network(tenant_id, net_id)
        ports_on_net = network['net-ports'].values()
        return ports_on_net

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        print("get_port_details() called\n")
        return self._get_port(tenant_id, net_id, port_id)
        
    def create_port(self, tenant_id, net_id, port_state=None):
        """
        Creates a port on the specified Virtual Network.
        """
        print("create_port() called\n")
        net = self._get_network(tenant_id, net_id)
        # check port state
        # TODO(salvatore-orlando): Validate port state in API?            
        self._validate_port_state(port_state)
        ports = net['net-ports']
        new_port_id = max(ports.keys()) + 1
        new_port_dict = {'port-id': new_port_id,
                         'port-state': port_state,
                         'attachment': None,
                         'portprofile': None}
        ports[new_port_id] = new_port_dict
        return new_port_dict 

    def update_port(self, tenant_id, net_id, port_id, port_state):
        """
        Updates the state of a port on the specified Virtual Network.
        """
        print("create_port() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        self._validate_port_state(port_state)
        port['port-state'] = port_state
        return port 
        
    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        print("delete_port() called\n")
        net = self._get_network(tenant_id, net_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port['attachment']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['attachment'])
        try:
            net['net-ports'].pop(int(port_id))
        except KeyError:  
            raise exc.PortNotFound(net_id=net_id, port_id=port_id)

    def get_interface_details(self, tenant_id, net_id, port_id):
        print("get interface detail called\n") 
        port = self._get_port(tenant_id, net_id, port_id)
        vid = port['attachment'] 
        if (vid == None):
            print("***no interface is attached")
            return "no interface attached"
        else:
            print("***interface id is " + vid)
            return ("attached interface " + vid)
        
    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        print("plug_interface() called\n")
        # Validate attachment
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port['attachment']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['attachment'])
        port['attachment'] = remote_interface_id
    
    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        print("unplug_interface() called\n")
        port = self._get_port(tenant_id, net_id, port_id)
        # TODO(salvatore-orlando):
        # Should unplug on port without attachment raise an Error?
        port['attachment'] = None
        
    def get_host(self, tenant_id, instance_id, instance_desc):
        print("associate an instance to a port....")
        print("get key2: " + instance_desc['key2'])
        return CiscoPaloPlugin2._host
    def get_instance_port(self, tenant_id, instance_id, instance_desc):
        print("get instance associated port....")
        print("get key1: " + instance_desc['key1'])
        return CiscoPaloPlugin2._vif