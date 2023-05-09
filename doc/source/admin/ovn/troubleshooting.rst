.. _ovn_troubleshooting:

===============
Troubleshooting
===============

The following section describe common problems that you might
encounter after/during the installation of the OVN ML2 driver with
Devstack and possible solutions to these problems.

Launching VM's failure
-----------------------

Disable AppArmor
~~~~~~~~~~~~~~~~

Using Ubuntu you might encounter libvirt permission errors when trying
to create OVS ports after launching a VM (from the nova compute log).
Disabling AppArmor might help with this problem, check out
https://help.ubuntu.com/community/AppArmor for instructions on how to
disable it.

Multi-Node setup not working
-----------------------------

Geneve kernel module not supported
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default OVN creates tunnels between compute nodes using the Geneve protocol.
Older kernels (< 3.18) don't support the Geneve module and hence tunneling
can't work.  You can check it with this command 'lsmod | grep openvswitch'
(geneve should show up in the result list)

For more information about which upstream Kernel version is required for
support of each tunnel type, see the answer to " Why do tunnels not work when
using a kernel module other than the one packaged with Open vSwitch?" in the
`OVS FAQ <http://docs.openvswitch.org/en/latest/faq/>`__.

MTU configuration
~~~~~~~~~~~~~~~~~

This problem is not unique to OVN but is amplified due to the possible larger
size of geneve header compared to other common tunneling protocols (VXLAN).
If you are using VM's as compute nodes make sure that you either lower the MTU
size on the virtual interface or enable fragmentation on it.

Duplicated or deleted OVN agents
--------------------------------

The "ovn-controller" process is the local controller daemon for OVN. It runs
in every host belonging to the OVN network and is in charge of registering
the host to the OVN database by creating the corresponding "Chassis" and
"Chassis_Private" registers in the Southbound database. At the same time,
when the process is gracefully stopped, it deletes both registers. These
registers are used by Neutron to control the OVN agents.

.. code-block:: console

  $ openstack network agent list -c ID -c "Agent Type" -c Host -c Alive -c State
  +--------------------------------------+------------------------------+--------+-------+-------+
  | ID                                   | Agent Type                   | Host   | Alive | State |
  +--------------------------------------+------------------------------+--------+-------+-------+
  | a55c8d85-2071-4452-92cb-95d15c29bde7 | OVN Controller Gateway agent | u20ovn | :-)   | UP    |
  | 62e29a01-a0ac-55c9-b4ec-e223d5c90853 | OVN Metadata agent           | u20ovn | :-)   | UP    |
  | ce9a1471-79c1-4472-adfc-9e5ce86eba07 | OVN Controller Gateway agent | u20ovn | XXX   | DOWN  |
  | 3755938f-9aac-4f08-a1ab-32fcff56d1ce | OVN Metadata agent           | u20ovn | XXX   | DOWN  |
  +--------------------------------------+------------------------------+--------+-------+-------+


If during a system upgrade the OVS "system-id" changes, the "Chassis" and
"Chassis_Private" registers will be created again but with a different UUID.
If the previous registers are not deleted (that should happen if the
"ovn-controller" process is gracefully stopped), Neutron will show duplicated
agents from the same host. In this case, only one agent will be alive and
the other one will be down because the "Chassis_Private.nb_cfg_timestamp"
is not updated. In this case, the administrator should manually delete from
the OVN Southbound database the stale registers. For example:

* List the "Chassis" registers, filtering by hostname and name (OVS
  "system-id"):

  .. code-block:: console

     $ sudo ovn-sbctl list Chassis | grep name
     hostname            : u20ovn
     name                : "a55c8d85-2071-4452-92cb-95d15c29bde7"
     hostname            : u20ovn
     name                : "ce9a1471-79c1-4472-adfc-9e5ce86eba07"

* Delete the stale "Chassis" register:

  .. code-block:: console

     $ sudo ovn-sbctl destroy Chassis ce9a1471-79c1-4472-adfc-9e5ce86eba07

* List the "Chassis_Private" registers, filtering by name:

  .. code-block:: console

     $ sudo ovn-sbctl list Chassis_Private | grep name
     name                : "a55c8d85-2071-4452-92cb-95d15c29bde7"
     name                : "ce9a1471-79c1-4472-adfc-9e5ce86eba07"

* Delete the stale "Chassis_Private" register:

  .. code-block:: console

     $ sudo ovn-sbctl destroy Chassis_Private ce9a1471-79c1-4472-adfc-9e5ce86eba07

If the host name is also updated during the system upgrade, the Neutron
agent list could present entries from different host names, but the older
ones will be down too. The procedure is the same.

It could also happen that during a node decommission, the "Chassis" register
is deleted but not the "Chassis_Private" one. In that case, the OVN agent
list will present the corresponding agents with the following message:
"('Chassis' register deleted)". Again, the procedure is the same: the
administrator should manually delete the orphaned OVN Southbound database
register. Neutron will receive this event and will delete the associated
OVN agents.
