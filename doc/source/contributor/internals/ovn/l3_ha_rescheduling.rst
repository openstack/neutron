.. _l3_ha_rescheduling:

===================================
L3 HA Scheduling of Gateway Chassis
===================================

Problem Description
-------------------

Currently if a single network node is active in the system, gateway chassis
for the routers would be scheduled on that node. However, when a new node is
added to the system, neither rescheduling nor rebalancing occur automatically.
This makes the router created on the first node to be not in HA mode.

Side-effects of this behavior include:

* Skewed up load on different network nodes due to lack of router rescheduling.

* If the active node, where the gateway chassis for a router is scheduled
  goes down, then because of lack of HA the North-South traffic from that
  router will be hampered.

Overview of Proposed Approach
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Gateway scheduling has been proposed in `[2]`_. However,  rebalancing or
rescheduling was not a part of that solution. This specification clarifies
what is rescheduling and rebalancing.
Rescheduling would automatically happen on every event triggered by
addition or deletion of chassis.
Rebalancing would be only triggered by manual operator action.

Rescheduling of Gateway Chassis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In order to provide proper rescheduling of the gateway ports during
addition or deletion of the chassis, following approach can be considered:

* Identify the number of chassis in which each router has been scheduled

  - Consider router for scheduling if no. of chassis < *MAX_GW_CHASSIS*

*MAX_GW_CHASSIS* is defined in `[0]`_

* Find a list of chassis where router is scheduled and reschedule it
  up to *MAX_GW_CHASSIS* gateways using list of available candidates.
  Do not modify the primary chassis association to not interrupt network flows.

Rescheduling is an event triggered operation which will occur whenever a
chassis is added or removed. When it happend, ``schedule_unhosted_gateways()``
`[1]`_ will be called to host the unhosted gateways. Routers without gateway
ports are excluded in this operation because those are not connected to
provider networks and haven't the gateway ports. More information about
it can be found in the ``gateway_chassis`` table definition in OVN
NorthBound DB `[5]`_.

Chassis which has the flag ``enable-chassis-as-gw`` enabled in their OVN
southbound database table, would be the ones eligible for hosting the routers.
Rescheduling of router depends on current prorities set. Each chassis is given
a specific priority for the router's gateway and priority increases with
increasing value ( i.e. 1 < 2 < 3 ...). The highest prioritized chassis hosts
gateway port. Other chassis are selected as backups.

There are two approaches for rescheduling supported by ovn driver right
now:
* Least loaded - select least-loaded chassis first,
* Random - select chassis randomly.

Few points to consider for the design:

* If there are 2 Chassis C1 and C2, where the routers are already balanced,
  and a new chassis C3 is added, then routers should be rescheduled only from
  C1 to C3 and C2 to C3. Rescheduling from C1 to C2 and vice-versa should not
  be allowed.

* In order to reschedule the router's chassis, the ``primary`` chassis for a
  gateway router will be left untouched. However, for the scenario where all
  routers are scheduled in only one chassis which is available as gateway,
  the addition of the second gateway chassis would schedule the router
  gateway ports at a lower priority on the new chassis.

Following scenarios are possible which have been considered in the design:

* Case #1:
    - System has only one chassis C1 and all router gateway ports are scheduled
      on it. We add a new chassis C2.
    - Behavior: All the routers scheduled on C1 will also be scheduled on C2
      with priority 1.
* Case #2:
    - System has 2 chassis C1 and C2 during installation. C1 goes down.
    - Behavior: In this case, all routers would be rescheduled to C2.
      Once C1 is back up, routers would be rescheduled on it. However,
      since C2 is now the new primary, routers on C1 would have lower priority.
* Case #3:
    - System has 2 chassis C1 and C2 during installation. C3 is added to it.
    - Behavior: In this case, routers would not move their primary chassis
      associations. So routers which have their primary on C1, would remain
      there, and same for routers on C2. However, lower proritized candidates
      of existing gateways would be scheduled on the chassis C3, depending
      on the type of used scheduler (Random or LeastLoaded).


Rebalancing of Gateway Chassis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Rebalancing is the second part of the design and it assigns a new primary to
already scheduled router gateway ports. Downtime is expected in this
operation. Rebalancing of routers can be achieved using external cli script.
Similar approach has been implemeneted for DHCP rescheduling `[4]`_.
The primary chassis gateway could be moved only to other, previously scheduled
gateway. Rebalancing of chassis occurs only if number of scheduled primary
chassis ports per each provider network hosted by given chassis is higher than
average number of hosted primary gateway ports per chassis per provider
network.

This dependency is determined by formula:

avg_gw_per_chassis = num_gw_by_provider_net / num_chassis_with_provider_net

Where:
    - avg_gw_per_chassis - average number of scheduler primary gateway chassis
      withing same provider network.
    - num_gw_by_provider_net - number of primary chassis gateways scheduled in
      given provider networks.
    - num_chassis_with_provider_net - number of chassis that has connectivity
      to given provider network.

The rebalancing occurs only if:

num_gw_by_provider_net_by_chassis > avg_gw_per_chassis

Where:
    - num_gw_by_provider_net_by_chassis - number of hosted primary gateways
      by given provider network by given chassis
    - avg_gw_per_chassis - average number of scheduler primary gateway chassis
      withing same provider network.


Following scenarios are possible which have been considered in the design:

* Case #1:
    - System has only two chassis C1 and C2. Chassis host the same number
      of gateways.
    - Behavior: Rebalancing doesn't occur.
* Case #2:
    - System has only two chassis C1 and C2. C1 hosts 3 gateways.
      C2 hosts 2 gateways.
    - Behavior: Rebalancing doesn't occur to not continuously move gateways
      between chassis in loop.
* Case #3:
    - System has two chassis C1 and C2. In meantime third chassis C3 has been
      added to the system.
    - Behavior: Rebalancing should occur. Gateways from C1 and C2 should be
      moved to C3 up to avg_gw_per_chassis.
* Case #4:
    - System has two chassis C1 and C2. C1 is connected to provnet1, but C2
      is connected to provnet2.
    - Behavior: Rebalancing shouldn't occur because of lack of chassis within
      same provider network.

References
~~~~~~~~~~
.. _`[0]`: https://opendev.org/openstack/neutron/src/commit/f73f39f2cfcd4eace2bda14c99ead9a8cc8560f4/neutron/common/ovn/constants.py#L171
.. _`[1]`: https://opendev.org/openstack/neutron/src/commit/f73f39f2cfcd4eace2bda14c99ead9a8cc8560f4/neutron/services/ovn_l3/plugin.py#L318
.. _`[2]`: https://bugs.launchpad.net/networking-ovn/+bug/1762694
.. _`[3]`: https://developer.openstack.org/api-ref/network/v2/index.html?expanded=schedule-router-to-an-l3-agent-detail#schedule-router-to-an-l3-agent
.. _`[4]`: https://opendev.org/x/osops-tools-contrib/src/branch/master/neutron/dhcp_agents_balancer.py
.. _`[5]`: http://www.openvswitch.org/support/dist-docs/ovn-nb.5.txt
