.. _ovn_igmp:

=======================================================
IP Multicast: IGMP snooping configuration guide for OVN
=======================================================

How to enable it
~~~~~~~~~~~~~~~~

In order to enable IGMP snooping with the OVN driver the following
configuration needs to be set in the ``/etc/neutron/neutron.conf``
file of the controller nodes:

.. code-block:: ini

   # OVN does reuse the OVS option, therefore the option group is [ovs]
   [ovs]
   igmp_snooping_enable = True
   ...

.. end

Upon restarting the Neutron service all existing networks (Logical_Switch,
in OVN terms) will be updated in OVN to enable or disable IGMP snooping
based on the ``igmp_snooping_enable`` configuration value.

.. note::

   Currently the OVN driver does not configure IGMP querier in OVN so
   ovn-controller will not send IGMP group memberships IP querier to
   retrieve IGMP membership reports from active members.


OVN Database information
~~~~~~~~~~~~~~~~~~~~~~~~

The ``igmp_snooping_enable`` configuration from Neutron is translated
into the ``mcast_snoop`` option set in the ``other_config`` column
from the ``Logical_Switch`` table in the OVN Northbound Database
(``mcast_flood_unregistered`` is always "false"):

.. code-block:: bash

   $ ovn-nbctl list Logical_Switch
   _uuid               : d6a2fbcd-aaa4-4b9e-8274-184238d66a15
   other_config        : {mcast_flood_unregistered="false", mcast_snoop="true"}
   ...

.. end


To find more information about the learnt IGMP groups by OVN use the
command below (populated only when igmp_snooping_enable is True):

.. code-block:: bash

    $ ovn-sbctl list IGMP_group
    _uuid               : 2d6cae4c-bd82-4b31-9c63-2d17cbeadc4e
    address             : "225.0.0.120"
    chassis             : 34e25681-f73f-43ac-a3a4-7da2a710ecd3
    datapath            : eaf0f5cc-a2c8-4c30-8def-2bc1ec9dcabc
    ports               : [5eaf9dd5-eae5-4749-ac60-4c1451901c56, 8a69efc5-38c5-48fb-bbab-30f2bf9b8d45]
    ...

.. end

.. note::

   Since IGMP querier is not yet supported in the OVN driver, restarting
   the ovn-controller service(s) will result in OVN unlearning the IGMP
   groups and broadcast all the multicast traffic. This behavior can
   impact when updating/upgrading the OVN services.


Extra information
~~~~~~~~~~~~~~~~~

When multicast IP traffic is sent to a multicast group address which
is in the **224.0.0.X** range, the multicast traffic will be flooded,
even when IGMP snooping is enabled. See the `RFC 4541 session 2.1.2`_::

   2) Packets with a destination IP (DIP) address in the 224.0.0.X range
      which are not IGMP must be forwarded on all ports.

The permutations from different configurations are:

* With IGMP snooping disabled: IP Multicast traffic flooded to all ports.

* With IGMP snooping enabled and multicast group address **not in**
  the 224.0.0.X range: IP Multicast traffic **is not** flooded.

* With IGMP snooping enabled and multicast group address **is in**
  the 224.0.0.X range: IP Multicast traffic **is** flooded.


.. _`RFC 4541 session 2.1.2`: https://tools.ietf.org/html/rfc4541
