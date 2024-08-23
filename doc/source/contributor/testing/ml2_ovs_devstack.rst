.. _ml2_ovs_devstack:

=====================
ML2 OVS with DevStack
=====================

This document describes how to test OpenStack Neutron with ML2 OpenvSwitch
using DevStack. We will start by describing how to test on a single host.

Single Node Test Environment
----------------------------

1. Create a test system.

It's best to use a throwaway dev system for running DevStack. Your best bet is
to use either CentOS 8 or the latest Ubuntu LTS.

2. Create the ``stack`` user.

::

     $ git clone https://opendev.org/openstack/devstack.git
     $ sudo ./devstack/tools/create-stack-user.sh

3. Switch to the ``stack`` user, copy Devstack to stack folder and clone
   Neutron.

::

     $ sudo cp -r devstack /opt/stack
     $ sudo chown -R stack:stack /opt/stack/devstack
     $ sudo su - stack
     $ cd /opt/stack
     $ git clone https://opendev.org/openstack/neutron.git

4. Configure DevStack to use the ML2 OVS driver.

Disable the OVN driver since it is the default ML2 driver for devstack
to Neutron. You may want to set some values for the various PASSWORD
variables in that file so DevStack doesn't have to prompt you for them.
Feel free to edit it if you'd like, but it should work as-is.

::

    $ cd devstack
    $ cp ../neutron/devstack/ml2-ovs-local.conf.sample local.conf

5. (Optional) Change the host IP to your local one

::

    $ cd devstack
    $ sed -i 's/#HOST_IP=.*/HOST_IP=172.16.189.6/g' local.conf

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

Next Steps
----------

* For ``Environment Variables`` please read `[Environment Variables] <ovn_devstack.html#environment-variables>`_
* For ``Default Network Configuration`` please read `[Default Network Configuration] <ovn_devstack.html#default-network-configuration>`_
* For ``Booting VMs`` please read `[Booting VMs] <ovn_devstack.html#booting-vms>`_
* For ``VM Connectivity`` please read `[VM Connectivity] <ovn_devstack.html#vm-connectivity>`_

Adding Another Node
-------------------

After completing the earlier instructions for setting up devstack, you can use
a second VM to emulate an additional compute or network node.
Create the ``stack`` user::

     $ git clone https://opendev.org/openstack/devstack.git
     $ sudo ./devstack/tools/create-stack-user.sh

Switch to the ``stack`` user and clone DevStack and neutron::

     $ sudo su - stack
     $ git clone https://opendev.org/openstack/devstack.git
     $ git clone https://opendev.org/openstack/neutron.git

Use the compute node sample configuration file to add new node, you
can enable some features or extensions like DVR, L2pop in this conf::

     $ cd devstack
     $ cp ../neutron/devstack/ml2-ovs-compute-local.conf.sample local.conf

.. note:: The config differences between compute node and network node are whether
          run the compute services and the L3 agent mode. So this sample local.conf
          can be used to add new network node.

You must set SERVICE_HOST in local.conf. The value should be the IP address of
the main DevStack host.  You must also set HOST_IP to the IP address of this
new host. See the text in the sample configuration file for more
information. Once that is complete, run DevStack::

    $ ./stack.sh

This should complete in less time than before, as it's only running a single
OpenStack service (nova-compute) along with neutron-openvswitch-agent,
neutron-l3-agent, neutron-dhcp-agent and neutron-metadata-agent.
The final output will look something like this::


    This is your host IP address: 172.16.189.30
    This is your host IPv6 address: ::1
    2017-03-09 18:39:27.058 | stack.sh completed in 1149 seconds.

Now go back to your main DevStack host to verify the install::

     $ . openrc
     $ openstack network agent list
     $ openstack compute service list

Testing
-------

Then we can following the steps at the testing page to do the following works,
for reference please read `Testing Neutron\'s related sections <testing.html>`_
