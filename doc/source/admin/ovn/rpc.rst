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
for example ML2/SRIOV, DHCP agents (for baremetal ports), etc. If the
configuration variable ``[DEFAULT]rpc_workers`` is set to 0, that means no
Neutron agent needs an RPC server; in that case, the ML2plugin will not
initialize any RPC client and no RPC notifications will be sent.

The ``OVNL3RouterPlugin`` class instantiates the RPC notifier handler but
doesn't assign an RPC instance. The ``ovn-router`` plugin doesn't have any
associated agent that requires RPC information.
