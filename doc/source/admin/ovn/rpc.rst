.. _ovn_rpc:

===================
RPC messages in OVN
===================

ML2/OVN driver uses the OVN NB tables ``Port_Group`` and ``ACL`` to
implement security groups. Security groups and security group rules are
directly sent to OVN NB via the OVSDB protocol. Neutron doesn't send any
RPC messages related to these topics when using the ML2/OVN mechanism
driver.

However, other RPC topics are kept in case other drivers are being used,
for example ML2/SRIOV, DHCP agents (for baremetal ports), etc.
