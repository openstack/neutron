====================
OpenVSwitch L2 Agent
====================

This Agent uses the `OpenVSwitch`_ virtual switch to create L2
connectivity for instances, along with bridges created in conjunction
with OpenStack Nova for filtering.

ovs-neutron-agent can be configured to use different networking technologies
to create tenant isolation.
These technologies are implemented as ML2 type drivers which are used in
conjunction with the OpenVSwitch mechanism driver.

VLAN Tags
---------

.. image:: images/under-the-hood-scenario-1-ovs-compute.png

.. _OpenVSwitch: http://openvswitch.org


GRE Tunnels
-----------

GRE Tunneling is documented in depth in the `Networking in too much
detail <http://openstack.redhat.com/Networking_in_too_much_detail>`_
by RedHat.


VXLAN Tunnels
-------------

VXLAN is an overlay technology which encapsulates MAC frames
at layer 2 into a UDP header.
More information can be found in `The VXLAN wiki page.
 <http://en.wikipedia.org/wiki/Virtual_Extensible_LAN>`_


Further Reading
---------------

* `Darragh O'Reilly - The Open vSwitch plugin with VLANs <http://techbackground.blogspot.com/2013/07/the-open-vswitch-plugin-with-vlans.html>`_
