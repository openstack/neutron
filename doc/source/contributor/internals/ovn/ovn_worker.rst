.. _ovn_worker:

===========================================
OVN Neutron Worker and Port status handling
===========================================

When the logical switch port's VIF is attached or removed to/from the ovn
integration bridge, ovn-northd updates the Logical_Switch_Port.up to 'True'
or 'False' accordingly.

In order for the OVN Neutron ML2 driver to update the corresponding neutron
port's status to 'ACTIVE' or 'DOWN' in the db, it needs to monitor the
OVN Northbound db. A neutron worker is created for this purpose.

The implementation of the ovn worker can be found here -
'networking_ovn.ovsdb.worker.OvnWorker'.

Neutron service will create 'n' api workers and 'm' rpc workers and 1 ovn
worker (all these workers are separate processes).

Api workers and rpc workers will create ovsdb idl client object
('ovs.db.idl.Idl') to connect to the OVN_Northbound db.
See 'networking_ovn.ovsdb.impl_idl_ovn.OvsdbNbOvnIdl' and
'ovsdbapp.backend.ovs_idl.connection.Connection' classes for more details.

Ovn worker will create 'networking_ovn.ovsdb.ovsdb_monitor.OvnIdl' class
object (which inherits from 'ovs.db.idl.Idl') to connect to the
OVN_Northbound db. On receiving the  OVN_Northbound db updates from the
ovsdb-server, 'notify' function of 'OVnIdl' is called by the parent class
object.

OvnIdl.notify() function passes the received events to the
ovsdb_monitor.OvnDbNotifyHandler class.
ovsdb_monitor.OvnDbNotifyHandler checks for any changes in
the 'Logical_Switch_Port.up' and updates the neutron port's status accordingly.

If 'notify_nova_on_port_status_changes' configuration is set, then neutron
would notify nova on port status changes.

ovsdb locks
-----------

If there are multiple neutron servers running, then each neutron server will
have one ovn worker which listens for the notify events. When the
'Logical_Switch_Port.up' is updated by ovn-northd, we do not want all the
neutron servers to handle the event and update the neutron port status.
In order for only one neutron server to handle the events, ovsdb locks are
used.

At start, each neutron server's ovn worker will try to acquire a lock with id -
'neutron_ovn_event_lock'. The ovn worker which has acquired the lock will
handle the notify events.

In case the neutron server with the lock dies, ovsdb-server will assign the
lock to another neutron server in the queue.

More details about the ovsdb locks can be found here [1] and [2]

[1] - https://tools.ietf.org/html/draft-pfaff-ovsdb-proto-04#section-4.1.8
[2] - https://github.com/openvswitch/ovs/blob/branch-2.4/python/ovs/db/idl.py#L67


One thing to note is the ovn worker (with OvnIdl) do not carry out any
transactions to the OVN Northbound db.

Since the api and rpc workers are not configured with any locks,
using the ovsdb lock on the OVN_Northbound and OVN_Southbound DBs by the ovn
workers will not have any side effects to the transactions done by these api
and rpc workers.

Handling port status changes when neutron server(s) are down
------------------------------------------------------------

When neutron server starts, ovn worker would receive a dump of all
logical switch ports as events. 'ovsdb_monitor.OvnDbNotifyHandler' would
sync up if there are any inconsistencies in the port status.

OVN Southbound DB Access
------------------------

The OVN Neutron ML2 driver has a need to acquire chassis information (hostname
and physnets combinations). This is required initially to support routed
networks. Thus, the plugin will initiate and maintain a connection to the OVN
SB DB during startup.
