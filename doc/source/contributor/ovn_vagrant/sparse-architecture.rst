.. _sparse-architecture:

===================
Sparse architecture
===================

The Vagrant scripts deploy OpenStack with Open Virtual Network (OVN)
using four nodes (five if you use the optional ovn-vtep node) to implement a
minimal variant of the reference architecture:

#. ovn-db: Database node containing the OVN northbound (NB) and southbound (SB)
   databases via the Open vSwitch (OVS) database and ``ovn-northd`` services.
#. ovn-controller: Controller node containing the Identity service, Image
   service, control plane portion of the Compute service, control plane
   portion of the Networking service including the ``ovn`` ML2
   driver, and the dashboard. In addition, the controller node is configured
   as an NFS server to support instance live migration between the two
   compute nodes.
#. ovn-compute1 and ovn-compute2: Two compute nodes containing the Compute
   hypervisor, ``ovn-controller`` service for OVN, metadata agents for the
   Networking service, and OVS services. In addition, the compute nodes are
   configured as NFS clients to support instance live migration between them.
#. ovn-vtep: Optional. A node to run the HW VTEP simulator. This node is not
   started by default but can be started by running "vagrant up ovn-vtep"
   after doing a normal "vagrant up".

During deployment, Vagrant creates three VirtualBox networks:

#. Vagrant management network for deployment and VM access to external
   networks such as the Internet. Becomes the VM ``eth0`` network interface.
#. OpenStack management network for the OpenStack control plane, OVN
   control plane, and OVN overlay networks. Becomes the VM ``eth1`` network
   interface.
#. OVN provider network that connects OpenStack instances to external networks
   such as the Internet. Becomes the VM ``eth2`` network interface.

Requirements
------------

The default configuration requires approximately 12 GB of RAM and supports
launching approximately four OpenStack instances using the ``m1.tiny``
flavor. You can change the amount of resources for each VM in the
``instances.yml`` file.

Deployment
----------

#. Follow the pre-requisites described in
   :doc:`/contributor/ovn_vagrant/prerequisites`

#. Clone the ``neutron`` repository locally and change to the
   ``neutron/vagrant/ovn/sparse`` directory::

     $ git clone https://opendev.org/openstack/neutron.git
     $ cd neutron/vagrant/ovn/sparse

#. If necessary, adjust any configuration in the ``instances.yml`` file.

   * If you change any IP addresses or networks, avoid conflicts with the
     host.
   * For evaluating large MTUs, adjust the ``mtu`` option. You must also
     change the MTU on the equivalent ``vboxnet`` interfaces on the host
     to the same value after Vagrant creates them. For example::

       # ip link set dev vboxnet0 mtu 9000
       # ip link set dev vboxnet1 mtu 9000

#. Launch the VMs and grab some coffee::

     $ vagrant up

#. After the process completes, you can use the ``vagrant status`` command
   to determine the VM status::

     $ vagrant status
     Current machine states:

     ovn-db                    running (virtualbox)
     ovn-controller            running (virtualbox)
     ovn-vtep                  running (virtualbox)
     ovn-compute1              running (virtualbox)
     ovn-compute2              running (virtualbox)

#. You can access the VMs using the following commands::

     $ vagrant ssh ovn-db
     $ vagrant ssh ovn-controller
     $ vagrant ssh ovn-vtep
     $ vagrant ssh ovn-compute1
     $ vagrant ssh ovn-compute2

   Note: If you prefer to use the VM console, the password for the ``root``
         account is ``vagrant``. Since ovn-controller is set as the primary
         in the Vagrantfile, the command ``vagrant ssh`` (without specifying
         the name) will connect ssh to that virtual machine.

#. Access OpenStack services via command-line tools on the ``ovn-controller``
   node or via the dashboard from the host by pointing a web browser at the
   IP address of the ``ovn-controller`` node.

   Note: By default, OpenStack includes two accounts: ``admin`` and ``demo``,
         both using password ``password``.

#. After completing your tasks, you can destroy the VMs::

     $ vagrant destroy
