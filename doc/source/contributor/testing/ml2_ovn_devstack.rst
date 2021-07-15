.. _ml2_ovn_devstack:

=========================
Testing OVN with DevStack
=========================

This document describes how to test OpenStack with OVN using DevStack. We will
start by describing how to test on a single host.

Single Node Test Environment
----------------------------

1. Create a test system.

It's best to use a throwaway dev system for running DevStack. Your best bet is
to use either CentOS 8 or the latest Ubuntu LTS (18.04, Bionic).

2. Create the ``stack`` user.

::

     $ git clone https://opendev.org/openstack/devstack.git
     $ sudo ./devstack/tools/create-stack-user.sh

3. Switch to the ``stack`` user and clone DevStack and Neutron.

::

     $ sudo su - stack
     $ git clone https://opendev.org/openstack/devstack.git
     $ git clone https://opendev.org/openstack/neutron.git

4. Configure DevStack to use the OVN driver.

OVN driver comes with a sample DevStack configuration file you can start
with.  For example, you may want to set some values for the various PASSWORD
variables in that file so DevStack doesn't have to prompt you for them.  Feel
free to edit it if you'd like, but it should work as-is.

::

    $ cd devstack
    $ cp ../neutron/devstack/ovn-local.conf.sample local.conf

5. Run DevStack.

This is going to take a while.  It installs a bunch of packages, clones a bunch
of git repos, and installs everything from these git repos.

::

    $ ./stack.sh

Once DevStack completes successfully, you should see output that looks
something like this::

    This is your host IP address: 172.16.189.6
    This is your host IPv6 address: ::1
    Horizon is now available at http://172.16.189.6/dashboard
    Keystone is serving at http://172.16.189.6/identity/
    The default users are: admin and demo
    The password: password
    2017-03-09 15:10:54.117 | stack.sh completed in 2110 seconds.

Environment Variables
---------------------

Once DevStack finishes successfully, we're ready to start interacting with
OpenStack APIs.  OpenStack provides a set of command line tools for interacting
with these APIs.  DevStack provides a file you can source to set up the right
environment variables to make the OpenStack command line tools work.

::

    $ . openrc

If you're curious what environment variables are set, they generally start with
an OS prefix::

    $ env | grep OS
    OS_REGION_NAME=RegionOne
    OS_IDENTITY_API_VERSION=2.0
    OS_PASSWORD=password
    OS_AUTH_URL=http://192.168.122.8:5000/v2.0
    OS_USERNAME=demo
    OS_TENANT_NAME=demo
    OS_VOLUME_API_VERSION=2
    OS_CACERT=/opt/stack/data/CA/int-ca/ca-chain.pem
    OS_NO_CACHE=1

Default Network Configuration
-----------------------------

By default, DevStack creates networks called ``private`` and ``public``.
Run the following command to see the existing networks::

    $ openstack network list
    +--------------------------------------+---------+----------------------------------------------------------------------------+
    | ID                                   | Name    | Subnets                                                                    |
    +--------------------------------------+---------+----------------------------------------------------------------------------+
    | 40080dad-0064-480a-b1b0-592ae51c1471 | private | 5ff81545-7939-4ae0-8365-1658d45fa85c, da34f952-3bfc-45bb-b062-d2d973c1a751 |
    | 7ec986dd-aae4-40b5-86cf-8668feeeab67 | public  | 60d0c146-a29b-4cd3-bd90-3745603b1a4b, f010c309-09be-4af2-80d6-e6af9c78bae7 |
    +--------------------------------------+---------+----------------------------------------------------------------------------+

A Neutron network is implemented as an OVN logical switch. OVN driver
creates logical switches with a name in the format neutron-<network UUID>.
We can use ``ovn-nbctl`` to list the configured logical switches and see that
their names correlate with the output from ``openstack network list``::

    $ ovn-nbctl ls-list
    71206f5c-b0e6-49ce-b572-eb2e964b2c4e (neutron-40080dad-0064-480a-b1b0-592ae51c1471)
    8d8270e7-fd51-416f-ae85-16565200b8a4 (neutron-7ec986dd-aae4-40b5-86cf-8668feeeab67)

    $ ovn-nbctl get Logical_Switch neutron-40080dad-0064-480a-b1b0-592ae51c1471 external_ids
    {"neutron:network_name"=private}

Booting VMs
-----------

In this section we'll go through the steps to create two VMs that have a
virtual NIC attached to the ``private`` Neutron network.

DevStack uses libvirt as the Nova backend by default.  If KVM is available, it
will be used.  Otherwise, it will just run qemu emulated guests.  This is
perfectly fine for our testing, as we only need these VMs to be able to send
and receive a small amount of traffic so performance is not very important.

1. Get the Network UUID.

Start by getting the UUID for the ``private`` network from the output of
``openstack network list`` from earlier and save it off::

    $ PRIVATE_NET_ID=$(openstack network show private -c id -f value)

2. Create an SSH keypair.

Next create an SSH keypair in Nova.  Later, when we boot a VM, we'll ask that
the public key be put in the VM so we can SSH into it.

::

    $ openstack keypair create demo > id_rsa_demo
    $ chmod 600 id_rsa_demo

3. Choose a flavor.

We need minimal resources for these test VMs, so the ``m1.nano`` flavor is
sufficient.

::

    $ openstack flavor list
    +----+-----------+-------+------+-----------+-------+-----------+
    | ID | Name      |   RAM | Disk | Ephemeral | VCPUs | Is Public |
    +----+-----------+-------+------+-----------+-------+-----------+
    | 1  | m1.tiny   |   512 |    1 |         0 |     1 | True      |
    | 2  | m1.small  |  2048 |   20 |         0 |     1 | True      |
    | 3  | m1.medium |  4096 |   40 |         0 |     2 | True      |
    | 4  | m1.large  |  8192 |   80 |         0 |     4 | True      |
    | 42 | m1.nano   |    64 |    0 |         0 |     1 | True      |
    | 5  | m1.xlarge | 16384 |  160 |         0 |     8 | True      |
    | 84 | m1.micro  |   128 |    0 |         0 |     1 | True      |
    | c1 | cirros256 |   256 |    0 |         0 |     1 | True      |
    | d1 | ds512M    |   512 |    5 |         0 |     1 | True      |
    | d2 | ds1G      |  1024 |   10 |         0 |     1 | True      |
    | d3 | ds2G      |  2048 |   10 |         0 |     2 | True      |
    | d4 | ds4G      |  4096 |   20 |         0 |     4 | True      |
    +----+-----------+-------+------+-----------+-------+-----------+

    $ FLAVOR_ID=$(openstack flavor show m1.nano -c id -f value)

4. Choose an image.

DevStack imports the CirrOS image by default, which is perfect for our testing.
It's a very small test image.

::

    $ openstack image list
    +--------------------------------------+--------------------------+--------+
    | ID                                   | Name                     | Status |
    +--------------------------------------+--------------------------+--------+
    | 849a8db2-3754-4cf6-9271-491fa4ff7195 | cirros-0.3.5-x86_64-disk | active |
    +--------------------------------------+--------------------------+--------+

    $ IMAGE_ID=$(openstack image list -c ID -f value)

5. Setup a security rule so that we can access the VMs we will boot up next.

By default, DevStack does not allow users to access VMs, to enable that, we
will need to add a rule.  We will allow both ICMP and SSH.

::

    $ openstack security group rule create --ingress --ethertype IPv4 --dst-port 22 --protocol tcp default
    $ openstack security group rule create --ingress --ethertype IPv4 --protocol ICMP default
    $ openstack security group rule list
    +--------------------------------------+-------------+-----------+------------+--------------------------------------+--------------------------------------+
    | ID                                   | IP Protocol | IP Range  | Port Range | Remote Security Group                | Security Group                       |
    +--------------------------------------+-------------+-----------+------------+--------------------------------------+--------------------------------------+
    ...
    | ade97198-db44-429e-9b30-24693d86d9b1 | tcp         | 0.0.0.0/0 | 22:22      | None                                 | a47b14da-5607-404a-8de4-3a0f1ad3649c |
    | d0861a98-f90e-4d1a-abfb-827b416bc2f6 | icmp        | 0.0.0.0/0 |            | None                                 | a47b14da-5607-404a-8de4-3a0f1ad3649c |
    ...
    +--------------------------------------+-------------+-----------+------------+--------------------------------------+--------------------------------------+

6. Boot some VMs.

Now we will boot two VMs.  We'll name them ``test1`` and ``test2``.

::

    $ openstack server create --nic net-id=$PRIVATE_NET_ID --flavor $FLAVOR_ID --image $IMAGE_ID --key-name demo test1
    +-----------------------------+-----------------------------------------------------------------+
    | Field                       | Value                                                           |
    +-----------------------------+-----------------------------------------------------------------+
    | OS-DCF:diskConfig           | MANUAL                                                          |
    | OS-EXT-AZ:availability_zone |                                                                 |
    | OS-EXT-STS:power_state      | NOSTATE                                                         |
    | OS-EXT-STS:task_state       | scheduling                                                      |
    | OS-EXT-STS:vm_state         | building                                                        |
    | OS-SRV-USG:launched_at      | None                                                            |
    | OS-SRV-USG:terminated_at    | None                                                            |
    | accessIPv4                  |                                                                 |
    | accessIPv6                  |                                                                 |
    | addresses                   |                                                                 |
    | adminPass                   | BzAWWA6byGP6                                                    |
    | config_drive                |                                                                 |
    | created                     | 2017-03-09T16:56:08Z                                            |
    | flavor                      | m1.nano (42)                                                    |
    | hostId                      |                                                                 |
    | id                          | d8b8084e-58ff-44f4-b029-a57e7ef6ba61                            |
    | image                       | cirros-0.3.5-x86_64-disk (849a8db2-3754-4cf6-9271-491fa4ff7195) |
    | key_name                    | demo                                                            |
    | name                        | test1                                                           |
    | progress                    | 0                                                               |
    | project_id                  | b6522570f7344c06b1f24303abf3c479                                |
    | properties                  |                                                                 |
    | security_groups             | name='default'                                                  |
    | status                      | BUILD                                                           |
    | updated                     | 2017-03-09T16:56:08Z                                            |
    | user_id                     | c68f77f1d85e43eb9e5176380a68ac1f                                |
    | volumes_attached            |                                                                 |
    +-----------------------------+-----------------------------------------------------------------+

    $ openstack server create --nic net-id=$PRIVATE_NET_ID --flavor $FLAVOR_ID --image $IMAGE_ID --key-name demo test2
    +-----------------------------+-----------------------------------------------------------------+
    | Field                       | Value                                                           |
    +-----------------------------+-----------------------------------------------------------------+
    | OS-DCF:diskConfig           | MANUAL                                                          |
    | OS-EXT-AZ:availability_zone |                                                                 |
    | OS-EXT-STS:power_state      | NOSTATE                                                         |
    | OS-EXT-STS:task_state       | scheduling                                                      |
    | OS-EXT-STS:vm_state         | building                                                        |
    | OS-SRV-USG:launched_at      | None                                                            |
    | OS-SRV-USG:terminated_at    | None                                                            |
    | accessIPv4                  |                                                                 |
    | accessIPv6                  |                                                                 |
    | addresses                   |                                                                 |
    | adminPass                   | YB8dmt5v88JV                                                    |
    | config_drive                |                                                                 |
    | created                     | 2017-03-09T16:56:50Z                                            |
    | flavor                      | m1.nano (42)                                                    |
    | hostId                      |                                                                 |
    | id                          | 170d4f37-9299-4a08-b48b-2b90fce8e09b                            |
    | image                       | cirros-0.3.5-x86_64-disk (849a8db2-3754-4cf6-9271-491fa4ff7195) |
    | key_name                    | demo                                                            |
    | name                        | test2                                                           |
    | progress                    | 0                                                               |
    | project_id                  | b6522570f7344c06b1f24303abf3c479                                |
    | properties                  |                                                                 |
    | security_groups             | name='default'                                                  |
    | status                      | BUILD                                                           |
    | updated                     | 2017-03-09T16:56:51Z                                            |
    | user_id                     | c68f77f1d85e43eb9e5176380a68ac1f                                |
    | volumes_attached            |                                                                 |
    +-----------------------------+-----------------------------------------------------------------+

Once both VMs have been started, they will have a status of ``ACTIVE``::

    $ openstack server list
    +--------------------------------------+-------+--------+---------------------------------------------------------+--------------------------+
    | ID                                   | Name  | Status | Networks                                                | Image Name               |
    +--------------------------------------+-------+--------+---------------------------------------------------------+--------------------------+
    | 170d4f37-9299-4a08-b48b-2b90fce8e09b | test2 | ACTIVE | private=fd5d:9d1b:457c:0:f816:3eff:fe24:49df, 10.0.0.3  | cirros-0.3.5-x86_64-disk |
    | d8b8084e-58ff-44f4-b029-a57e7ef6ba61 | test1 | ACTIVE | private=fd5d:9d1b:457c:0:f816:3eff:fe3f:953d, 10.0.0.10 | cirros-0.3.5-x86_64-disk |
    +--------------------------------------+-------+--------+---------------------------------------------------------+--------------------------+

Our two VMs have addresses of ``10.0.0.3`` and ``10.0.0.10``.  If we list
Neutron ports, there are two new ports with these addresses associated
with them::

    $ openstack port list
    +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+
    | ID                                   | Name | MAC Address       | Fixed IP Addresses                                                                                  | Status |
    +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+
    ...
    | 97c970b0-485d-47ec-868d-783c2f7acde3 |      | fa:16:3e:3f:95:3d | ip_address='10.0.0.10', subnet_id='da34f952-3bfc-45bb-b062-d2d973c1a751'                            | ACTIVE |
    |                                      |      |                   | ip_address='fd5d:9d1b:457c:0:f816:3eff:fe3f:953d', subnet_id='5ff81545-7939-4ae0-8365-1658d45fa85c' |        |
    | e003044d-334a-4de3-96d9-35b2d2280454 |      | fa:16:3e:24:49:df | ip_address='10.0.0.3', subnet_id='da34f952-3bfc-45bb-b062-d2d973c1a751'                             | ACTIVE |
    |                                      |      |                   | ip_address='fd5d:9d1b:457c:0:f816:3eff:fe24:49df', subnet_id='5ff81545-7939-4ae0-8365-1658d45fa85c' |        |
    ...
    +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+


Now we can look at OVN using ``ovn-nbctl`` to see the logical switch ports
that were created for these two Neutron ports.  The first part of the output
is the OVN logical switch port UUID.  The second part in parentheses is the
logical switch port name. Neutron sets the logical switch port name equal to
the Neutron port ID.

::

    $ ovn-nbctl lsp-list neutron-$PRIVATE_NET_ID
    ...
    fde1744b-e03b-46b7-b181-abddcbe60bf2 (97c970b0-485d-47ec-868d-783c2f7acde3)
    7ce284a8-a48a-42f5-bf84-b2bca62cd0fe (e003044d-334a-4de3-96d9-35b2d2280454)
    ...


These two ports correspond to the two VMs we created.

VM Connectivity
---------------

We can connect to our VMs by associating a floating IP address from the public
network.

::

    $ TEST1_PORT_ID=$(openstack port list --server test1 -c id -f value)
    $ openstack floating ip create --port $TEST1_PORT_ID public
    +---------------------+--------------------------------------+
    | Field               | Value                                |
    +---------------------+--------------------------------------+
    | created_at          | 2017-03-09T18:58:12Z                 |
    | description         |                                      |
    | fixed_ip_address    | 10.0.0.10                            |
    | floating_ip_address | 172.24.4.8                           |
    | floating_network_id | 7ec986dd-aae4-40b5-86cf-8668feeeab67 |
    | id                  | 24ff0799-5a72-4a5b-abc0-58b301c9aee5 |
    | name                | None                                 |
    | port_id             | 97c970b0-485d-47ec-868d-783c2f7acde3 |
    | project_id          | b6522570f7344c06b1f24303abf3c479     |
    | revision_number     | 1                                    |
    | router_id           | ee51adeb-0dd8-4da0-ab6f-7ce60e00e7b0 |
    | status              | DOWN                                 |
    | updated_at          | 2017-03-09T18:58:12Z                 |
    +---------------------+--------------------------------------+

Devstack does not wire up the public network by default so we must do
that before connecting to this floating IP address.

::

    $ sudo ip link set br-ex up
    $ sudo ip route add 172.24.4.0/24 dev br-ex
    $ sudo ip addr add 172.24.4.1/24 dev br-ex

Now you should be able to connect to the VM via its floating IP address.
First, ping the address.

::

    $ ping -c 1 172.24.4.8
    PING 172.24.4.8 (172.24.4.8) 56(84) bytes of data.
    64 bytes from 172.24.4.8: icmp_seq=1 ttl=63 time=0.823 ms

    --- 172.24.4.8 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 0.823/0.823/0.823/0.000 ms

Now SSH to the VM::

    $ ssh -i id_rsa_demo cirros@172.24.4.8 hostname
    test1

Adding Another Compute Node
---------------------------

After completing the earlier instructions for setting up devstack, you can use
a second VM to emulate an additional compute node.  This is important for OVN
testing as it exercises the tunnels created by OVN between the hypervisors.

Just as before, create a throwaway VM but make sure that this VM has a
different host name. Having same host name for both VMs will confuse Nova and
will not produce two hypervisors when you query nova hypervisor list later.
Once the VM is setup, create the ``stack`` user::

     $ git clone https://opendev.org/openstack/devstack.git
     $ sudo ./devstack/tools/create-stack-user.sh

Switch to the ``stack`` user and clone DevStack and neutron::

     $ sudo su - stack
     $ git clone https://opendev.org/openstack/devstack.git
     $ git clone https://opendev.org/openstack/neutron.git

OVN comes with another sample configuration file that can be used
for this::

     $ cd devstack
     $ cp ../neutron/devstack/ovn-compute-local.conf.sample local.conf

You must set SERVICE_HOST in local.conf.  The value should be the IP address of
the main DevStack host.  You must also set HOST_IP to the IP address of this
new host.  See the text in the sample configuration file for more
information.  Once that is complete, run DevStack::

    $ cd devstack
    $ ./stack.sh

This should complete in less time than before, as it's only running a single
OpenStack service (nova-compute) along with OVN (ovn-controller, ovs-vswitchd,
ovsdb-server).  The final output will look something like this::


    This is your host IP address: 172.16.189.30
    This is your host IPv6 address: ::1
    2017-03-09 18:39:27.058 | stack.sh completed in 1149 seconds.

Now go back to your main DevStack host.  You can use admin credentials to
verify that the additional hypervisor has been added to the deployment::

    $ cd devstack
    $ . openrc admin
    $ ./tools/discover_hosts.sh
    $ openstack hypervisor list
    +----+------------------------+-----------------+---------------+-------+
    | ID | Hypervisor Hostname    | Hypervisor Type | Host IP       | State |
    +----+------------------------+-----------------+---------------+-------+
    |  1 | centos7-ovn-devstack   | QEMU            | 172.16.189.6  | up    |
    |  2 | centos7-ovn-devstack-2 | QEMU            | 172.16.189.30 | up    |
    +----+------------------------+-----------------+---------------+-------+

You can also look at OVN and OVS to see that the second host has shown up.  For
example, there will be a second entry in the Chassis table of the
OVN_Southbound database.  You can use the ``ovn-sbctl`` utility to list
chassis, their configuration, and the ports bound to each of them::

    $ ovn-sbctl show

    Chassis "ddc8991a-d838-4758-8d15-71032da9d062"
        hostname: "centos7-ovn-devstack"
        Encap vxlan
            ip: "172.16.189.6"
            options: {csum="true"}
        Encap geneve
            ip: "172.16.189.6"
            options: {csum="true"}
        Port_Binding "97c970b0-485d-47ec-868d-783c2f7acde3"
        Port_Binding "e003044d-334a-4de3-96d9-35b2d2280454"
        Port_Binding "cr-lrp-08d1f28d-cc39-4397-b12b-7124080899a1"
    Chassis "b194d07e-0733-4405-b795-63b172b722fd"
        hostname: "centos7-ovn-devstack-2.os1.phx2.redhat.com"
        Encap geneve
            ip: "172.16.189.30"
            options: {csum="true"}
        Encap vxlan
            ip: "172.16.189.30"
            options: {csum="true"}

You can also see a tunnel created to the other compute node::

    $ ovs-vsctl show
    ...
    Bridge br-int
        fail_mode: secure
        ...
        Port "ovn-b194d0-0"
            Interface "ovn-b194d0-0"
                type: geneve
                options: {csum="true", key=flow, remote_ip="172.16.189.30"}
        ...
    ...

Provider Networks
-----------------

Neutron has a "provider networks" API extension that lets you specify
some additional attributes on a network.  These attributes let you
map a Neutron network to a physical network in your environment.
The OVN ML2 driver is adding support for this API extension.  It currently
supports "flat" and "vlan" networks.

Here is how you can test it:

First you must create an OVS bridge that provides connectivity to the
provider network on every host running ovn-controller.  For trivial
testing this could just be a dummy bridge.  In a real environment, you
would want to add a local network interface to the bridge, as well.

::

    $ ovs-vsctl add-br br-provider

ovn-controller on each host must be configured with a mapping between
a network name and the bridge that provides connectivity to that network.
In this case we'll create a mapping from the network name "providernet"
to the bridge 'br-provider".

::

    $ ovs-vsctl set open . \
    external-ids:ovn-bridge-mappings=providernet:br-provider

If you want to enable this chassis to host a gateway router for
external connectivity, then set ovn-cms-options to enable-chassis-as-gw.

::

    $ ovs-vsctl set open . \
    external-ids:ovn-cms-options="enable-chassis-as-gw"

Now create a Neutron provider network.

::

    $ openstack network create provider --share \
    --provider-physical-network providernet \
    --provider-network-type flat

Alternatively, you can define connectivity to a VLAN instead of a flat network:

::

    $ openstack network create provider-101 --share \
    --provider-physical-network providernet \
    --provider-network-type vlan
    --provider-segment 101

Observe that the OVN ML2 driver created a special logical switch port of type
localnet on the logical switch to model the connection to the physical network.

::

    $ ovn-nbctl show
    ...
     switch 5bbccbbd-f5ca-411b-bad9-01095d6f1316 (neutron-729dbbee-db84-4a3d-afc3-82c0b3701074)
         port provnet-729dbbee-db84-4a3d-afc3-82c0b3701074
             addresses: ["unknown"]
    ...

    $ ovn-nbctl lsp-get-type provnet-729dbbee-db84-4a3d-afc3-82c0b3701074
    localnet

    $ ovn-nbctl lsp-get-options provnet-729dbbee-db84-4a3d-afc3-82c0b3701074
    network_name=providernet

If VLAN is used, there will be a VLAN tag shown on the localnet port as well.

Finally, create a Neutron port on the provider network.

::

    $ openstack port create --network provider myport

or if you followed the VLAN example, it would be:

::

    $ openstack port create --network provider-101 myport

Skydive
-------

`Skydive <https://github.com/skydive-project/skydive>`_ is an open source
real-time network topology and protocols analyzer. It aims to provide a
comprehensive way of understanding what is happening in the network
infrastructure. Skydive works by utilizing agents to collect host-local
information, and sending this information to a central agent for
further analysis. It utilizes elasticsearch to store the data.

To enable Skydive support with OVN and devstack, enable it on the control
and compute nodes.

On the control node, enable it as follows:

::

    enable_plugin skydive https://github.com/skydive-project/skydive.git
    enable_service skydive-analyzer

On the compute nodes, enable it as follows:

::

    enable_plugin skydive https://github.com/skydive-project/skydive.git
    enable_service skydive-agent

Troubleshooting
---------------

If you run into any problems, take a look at our :doc:`/admin/ovn/troubleshooting`
page.

Additional Resources
--------------------

See the documentation and other references linked
from the :doc:`/admin/ovn/ovn` page.
