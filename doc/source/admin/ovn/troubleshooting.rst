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
