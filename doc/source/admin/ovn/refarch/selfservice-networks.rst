.. _refarch-selfservice-networks:

Self-service networks
---------------------

A self-service (project) network includes only virtual components, thus
enabling projects to manage them without additional configuration of the
underlying physical network. The OVN mechanism driver supports Geneve
and VLAN network types with a preference toward Geneve. Projects can
choose to isolate self-service networks, connect two or more together
via routers, or connect them to provider networks via routers with
appropriate capabilities. Similar to provider networks, self-service
networks can use arbitrary names.

.. note::

   Similar to provider networks, self-service VLAN networks map to a
   unique bridge on each compute node that supports launching instances
   on those networks. Self-service VLAN networks also require several
   commands at the host and OVS levels. The following example assumes
   use of Geneve self-service networks.

Create a self-service network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creating a self-service network involves several commands at the
Networking service level that yield a series of operations at the OVN
level to create the virtual network components. The following example
creates a Geneve self-service network and binds a subnet to it. The
subnet uses DHCP to distribute IP addresses to instances.

#. On the controller node, source the credentials for a regular
   (non-privileged) project. The following example uses the ``demo``
   project.

#. On the controller node, create a self-service network in the Networking
   service.

   .. code-block:: console

      $ openstack network create selfservice
      +-------------------------+--------------------------------------+
      | Field                   | Value                                |
      +-------------------------+--------------------------------------+
      | admin_state_up          | UP                                   |
      | availability_zone_hints |                                      |
      | availability_zones      |                                      |
      | created_at              | 2016-06-09T15:42:41                  |
      | description             |                                      |
      | id                      | f49791f7-e653-4b43-99b1-0f5557c313e4 |
      | ipv4_address_scope      | None                                 |
      | ipv6_address_scope      | None                                 |
      | mtu                     | 1442                                 |
      | name                    | selfservice                          |
      | port_security_enabled   | True                                 |
      | project_id              | 1ef26f483b9d44e8ac0c97388d6cb609     |
      | router_external         | Internal                             |
      | shared                  | False                                |
      | status                  | ACTIVE                               |
      | subnets                 |                                      |
      | tags                    | []                                   |
      | updated_at              | 2016-06-09T15:42:41                  |
      +-------------------------+--------------------------------------+

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations
during creation of a self-service network.

#. The mechanism driver translates the network into a logical switch in
   the OVN northbound database.

   .. code-block:: console

      uuid               : 0ab40684-7cf8-4d6c-ae8b-9d9143762d37
      acls                : []
      external_ids        : {"neutron:network_name"="selfservice"}
      name                : "neutron-d5aadceb-d8d6-41c8-9252-c5e0fe6c26a5"
      ports               : []

#. The OVN northbound service translates this object into new datapath
   bindings and logical flows in the OVN southbound database.

   * Datapath bindings

     .. code-block:: console

        _uuid               : 0b214af6-8910-489c-926a-fd0ed16a8251
        external_ids        : {logical-switch="15e2c80b-1461-4003-9869-80416cd97de5"}
        tunnel_key          : 5

   * Logical flows

     .. code-block:: console

        Datapath: 0b214af6-8910-489c-926a-fd0ed16a8251  Pipeline: ingress
          table= 0(  ls_in_port_sec_l2), priority=  100, match=(eth.src[40]),
            action=(drop;)
          table= 0(  ls_in_port_sec_l2), priority=  100, match=(vlan.present),
            action=(drop;)
          table= 1(  ls_in_port_sec_ip), priority=    0, match=(1),
            action=(next;)
          table= 2(  ls_in_port_sec_nd), priority=    0, match=(1),
            action=(next;)
          table= 3(      ls_in_pre_acl), priority=    0, match=(1),
            action=(next;)
          table= 4(       ls_in_pre_lb), priority=    0, match=(1),
            action=(next;)
          table= 5( ls_in_pre_stateful), priority=  100, match=(reg0[0] == 1),
            action=(ct_next;)
          table= 5( ls_in_pre_stateful), priority=    0, match=(1),
            action=(next;)
          table= 6(          ls_in_acl), priority=    0, match=(1),
            action=(next;)
          table= 7(           ls_in_lb), priority=    0, match=(1),
            action=(next;)
          table= 8(     ls_in_stateful), priority=  100, match=(reg0[2] == 1),
            action=(ct_lb;)
          table= 8(     ls_in_stateful), priority=  100, match=(reg0[1] == 1),
            action=(ct_commit; next;)
          table= 8(     ls_in_stateful), priority=    0, match=(1),
            action=(next;)
          table= 9(      ls_in_arp_rsp), priority=    0, match=(1),
            action=(next;)
          table=10(      ls_in_l2_lkup), priority=  100, match=(eth.mcast),
            action=(outport = "_MC_flood"; output;)
        Datapath: 0b214af6-8910-489c-926a-fd0ed16a8251  Pipeline: egress
          table= 0(      ls_out_pre_lb), priority=    0, match=(1),
            action=(next;)
          table= 1(     ls_out_pre_acl), priority=    0, match=(1),
            action=(next;)
          table= 2(ls_out_pre_stateful), priority=  100, match=(reg0[0] == 1),
            action=(ct_next;)
          table= 2(ls_out_pre_stateful), priority=    0, match=(1),
            action=(next;)
          table= 3(          ls_out_lb), priority=    0, match=(1),
            action=(next;)
          table= 4(         ls_out_acl), priority=    0, match=(1),
            action=(next;)
          table= 5(    ls_out_stateful), priority=  100, match=(reg0[1] == 1),
            action=(ct_commit; next;)
          table= 5(    ls_out_stateful), priority=  100, match=(reg0[2] == 1),
            action=(ct_lb;)
          table= 5(    ls_out_stateful), priority=    0, match=(1),
            action=(next;)
          table= 6( ls_out_port_sec_ip), priority=    0, match=(1),
            action=(next;)
          table= 7( ls_out_port_sec_l2), priority=  100, match=(eth.mcast),
            action=(output;)

   .. note::

      These actions do not create flows on any nodes.

Create a subnet on the self-service network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A self-service network requires at least one subnet. In most cases,
the environment provides suitable values for IP address allocation for
instances, default gateway IP address, and metadata such as name
resolution.

#. On the controller node, create a subnet bound to the self-service network
   ``selfservice``.

   .. code-block:: console

      $ openstack subnet create --network selfservice --subnet-range 192.168.1.0/24 selfservice-v4
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 192.168.1.2-192.168.1.254            |
      | cidr              | 192.168.1.0/24                       |
      | created_at        | 2016-06-16 00:19:08+00:00            |
      | description       |                                      |
      | dns_nameservers   |                                      |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 192.168.1.1                          |
      | headers           |                                      |
      | host_routes       |                                      |
      | id                | 8f027f25-0112-45b9-a1b9-2f8097c57219 |
      | ip_version        | 4                                    |
      | ipv6_address_mode | None                                 |
      | ipv6_ra_mode      | None                                 |
      | name              | selfservice-v4                       |
      | network_id        | 8ed4e43b-63ef-41ed-808b-b59f1120aec0 |
      | project_id        | b1ebf33664df402693f729090cfab861     |
      | subnetpool_id     | None                                 |
      | updated_at        | 2016-06-16 00:19:08+00:00            |
      +-------------------+--------------------------------------+


OVN operations
^^^^^^^^^^^^^^

.. todo: Update this part with the new agentless DHCP details

The OVN mechanism driver and OVN perform the following operations
during creation of a subnet on a self-service network.

#. If the subnet uses DHCP for IP address management, create logical ports
   ports for each DHCP agent serving the subnet and bind them to the logical
   switch. In this example, the subnet contains two DHCP agents.

   .. code-block:: console

      _uuid               : 1ed7c28b-dc69-42b8-bed6-46477bb8b539
      addresses           : ["fa:16:3e:94:db:5e 192.168.1.2"]
      enabled             : true
      external_ids        : {"neutron:port_name"=""}
      name                : "0cfbbdca-ff58-4cf8-a7d3-77daaebe3056"
      options             : {}
      parent_name         : []
      port_security       : []
      tag                 : []
      type                : ""
      up                  : true

      _uuid               : ae10a5e0-db25-4108-b06a-d2d5c127d9c4
      addresses           : ["fa:16:3e:90:bd:f1 192.168.1.3"]
      enabled             : true
      external_ids        : {"neutron:port_name"=""}
      name                : "74930ace-d939-4bca-b577-fccba24c3fca"
      options             : {}
      parent_name         : []
      port_security       : []
      tag                 : []
      type                : ""
      up                  : true

      _uuid               : 0ab40684-7cf8-4d6c-ae8b-9d9143762d37
      acls                : []
      external_ids        : {"neutron:network_name"="selfservice"}
      name                : "neutron-d5aadceb-d8d6-41c8-9252-c5e0fe6c26a5"
      ports               : [1ed7c28b-dc69-42b8-bed6-46477bb8b539,
                            ae10a5e0-db25-4108-b06a-d2d5c127d9c4]

#. The OVN northbound service creates port bindings for these logical
   ports and adds them to the appropriate multicast group.

   * Port bindings

     .. code-block:: console

        _uuid               : 3e463ca0-951c-46fd-b6cf-05392fa3aa1f
        chassis             : 6a9d0619-8818-41e6-abef-2f3d9a597c03
        datapath            : 0b214af6-8910-489c-926a-fd0ed16a8251
        logical_port        : "a203b410-97c1-4e4a-b0c3-558a10841c16"
        mac                 : ["fa:16:3e:a1:dc:58 192.168.1.3"]
        options             : {}
        parent_port         : []
        tag                 : []
        tunnel_key          : 2
        type                : ""

        _uuid               : fa7b294d-2a62-45ae-8de3-a41c002de6de
        chassis             : d63e8ae8-caf3-4a6b-9840-5c3a57febcac
        datapath            : 0b214af6-8910-489c-926a-fd0ed16a8251
        logical_port        : "39b23721-46f4-4747-af54-7e12f22b3397"
        mac                 : ["fa:16:3e:1a:b4:23 192.168.1.2"]
        options             : {}
        parent_port         : []
        tag                 : []
        tunnel_key          : 1
        type                : ""

   * Multicast groups

     .. code-block:: console

        _uuid               : c08d0102-c414-4a47-98d9-dd3fa9f9901c
        datapath            : 0b214af6-8910-489c-926a-fd0ed16a8251
        name                : _MC_flood
        ports               : [3e463ca0-951c-46fd-b6cf-05392fa3aa1f,
                               fa7b294d-2a62-45ae-8de3-a41c002de6de]
        tunnel_key          : 65535

#. The OVN northbound service translates the logical ports into logical flows
   in the OVN southbound database.

   .. code-block:: console

      Datapath: 0b214af6-8910-489c-926a-fd0ed16a8251  Pipeline: ingress
        table= 0(  ls_in_port_sec_l2), priority=   50,
          match=(inport == "39b23721-46f4-4747-af54-7e12f22b3397"),
          action=(next;)
        table= 0(  ls_in_port_sec_l2), priority=   50,
          match=(inport == "a203b410-97c1-4e4a-b0c3-558a10841c16"),
          action=(next;)
        table= 9(      ls_in_arp_rsp), priority=   50,
          match=(arp.tpa == 192.168.1.2 && arp.op == 1),
          action=(eth.dst = eth.src; eth.src = fa:16:3e:1a:b4:23;
                  arp.op = 2; /* ARP reply */ arp.tha = arp.sha;
                  arp.sha = fa:16:3e:1a:b4:23; arp.tpa = arp.spa;
                  arp.spa = 192.168.1.2; outport = inport;
                  inport = ""; /* Allow sending out inport. */ output;)
        table= 9(      ls_in_arp_rsp), priority=   50,
          match=(arp.tpa == 192.168.1.3 && arp.op == 1),
          action=(eth.dst = eth.src; eth.src = fa:16:3e:a1:dc:58;
                  arp.op = 2; /* ARP reply */ arp.tha = arp.sha;
                  arp.sha = fa:16:3e:a1:dc:58; arp.tpa = arp.spa;
                  arp.spa = 192.168.1.3; outport = inport;
                  inport = ""; /* Allow sending out inport. */ output;)
        table=10(      ls_in_l2_lkup), priority=   50,
          match=(eth.dst == fa:16:3e:a1:dc:58),
          action=(outport = "a203b410-97c1-4e4a-b0c3-558a10841c16"; output;)
        table=10(      ls_in_l2_lkup), priority=   50,
          match=(eth.dst == fa:16:3e:1a:b4:23),
          action=(outport = "39b23721-46f4-4747-af54-7e12f22b3397"; output;)
      Datapath: 0b214af6-8910-489c-926a-fd0ed16a8251  Pipeline: egress
        table= 7( ls_out_port_sec_l2), priority=   50,
          match=(outport == "39b23721-46f4-4747-af54-7e12f22b3397"),
          action=(output;)
        table= 7( ls_out_port_sec_l2), priority=   50,
          match=(outport == "a203b410-97c1-4e4a-b0c3-558a10841c16"),
          action=(output;)

#. For each compute node without a DHCP agent on the subnet:

   * The OVN controller service translates these objects into flows on the
     integration bridge ``br-int``.

     .. code-block:: console

        # ovs-ofctl dump-flows br-int
        cookie=0x0, duration=9.054s, table=32, n_packets=0, n_bytes=0,
            idle_age=9, priority=100,reg7=0xffff,metadata=0x5
            actions=load:0x5->NXM_NX_TUN_ID[0..23],
                set_field:0xffff/0xffffffff->tun_metadata0,
                move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],
                output:4,output:3

#. For each compute node with a DHCP agent on the subnet:

   * Creation of a DHCP network namespace adds a virtual switch ports that
     connects the DHCP agent with the ``dnsmasq`` process to the integration
     bridge.

     .. code-block:: console

        # ovs-ofctl show br-int
        OFPT_FEATURES_REPLY (xid=0x2): dpid:000022024a1dc045
        n_tables:254, n_buffers:256
        capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
        actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
         9(tap39b23721-46): addr:00:00:00:00:b0:5d
             config:     PORT_DOWN
             state:      LINK_DOWN
             speed: 0 Mbps now, 0 Mbps max

   * The OVN controller service translates these objects into flows on the
     integration bridge.

     .. code-block:: console

        cookie=0x0, duration=21.074s, table=0, n_packets=8, n_bytes=648,
            idle_age=11, priority=100,in_port=9
            actions=load:0x2->NXM_NX_REG5[],load:0x5->OXM_OF_METADATA[],
                load:0x1->NXM_NX_REG6[],resubmit(,16)
        cookie=0x0, duration=21.076s, table=16, n_packets=0, n_bytes=0,
            idle_age=21, priority=100,metadata=0x5,
                dl_src=01:00:00:00:00:00/01:00:00:00:00:00
            actions=drop
        cookie=0x0, duration=21.075s, table=16, n_packets=0, n_bytes=0,
            idle_age=21, priority=100,metadata=0x5,vlan_tci=0x1000/0x1000
            actions=drop
        cookie=0x0, duration=21.076s, table=16, n_packets=0, n_bytes=0,
            idle_age=21, priority=50,reg6=0x2,metadata=0x5
            actions=resubmit(,17)
        cookie=0x0, duration=21.075s, table=16, n_packets=8, n_bytes=648,
            idle_age=11, priority=50,reg6=0x1,metadata=0x5
            actions=resubmit(,17)
        cookie=0x0, duration=21.075s, table=17, n_packets=8, n_bytes=648,
            idle_age=11, priority=0,metadata=0x5
            actions=resubmit(,18)
        cookie=0x0, duration=21.076s, table=18, n_packets=8, n_bytes=648,
            idle_age=11, priority=0,metadata=0x5
            actions=resubmit(,19)
        cookie=0x0, duration=21.076s, table=19, n_packets=8, n_bytes=648,
            idle_age=11, priority=0,metadata=0x5
            actions=resubmit(,20)
        cookie=0x0, duration=21.075s, table=20, n_packets=8, n_bytes=648,
            idle_age=11, priority=0,metadata=0x5
            actions=resubmit(,21)
        cookie=0x0, duration=5.398s, table=21, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ipv6,reg0=0x1/0x1,metadata=0x5
            actions=ct(table=22,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=5.398s, table=21, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ip,reg0=0x1/0x1,metadata=0x5
            actions=ct(table=22,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=5.398s, table=22, n_packets=6, n_bytes=508,
            idle_age=2, priority=0,metadata=0x5
            actions=resubmit(,23)
        cookie=0x0, duration=5.398s, table=23, n_packets=6, n_bytes=508,
            idle_age=2, priority=0,metadata=0x5
            actions=resubmit(,24)
        cookie=0x0, duration=5.398s, table=24, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ipv6,reg0=0x4/0x4,metadata=0x5
            actions=ct(table=25,zone=NXM_NX_REG5[0..15],nat)
        cookie=0x0, duration=5.398s, table=24, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ip,reg0=0x4/0x4,metadata=0x5
            actions=ct(table=25,zone=NXM_NX_REG5[0..15],nat)
        cookie=0x0, duration=5.398s, table=24, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ipv6,reg0=0x2/0x2,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,25)
        cookie=0x0, duration=5.398s, table=24, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ip,reg0=0x2/0x2,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,25)
        cookie=0x0, duration=5.399s, table=24, n_packets=6, n_bytes=508,
            idle_age=2, priority=0,metadata=0x5 actions=resubmit(,25)
        cookie=0x0, duration=5.398s, table=25, n_packets=0, n_bytes=0,
            idle_age=5, priority=50,arp,metadata=0x5,
                arp_tpa=192.168.1.2,arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:82:8b:0e,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e828b0e->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a80102->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
                load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=5.378s, table=25, n_packets=0, n_bytes=0,
            idle_age=5, priority=50,arp,metadata=0x5,arp_tpa=192.168.1.3,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:d5:00:02,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163ed50002->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a80103->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
                load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=5.399s, table=25, n_packets=6, n_bytes=508,
            idle_age=2, priority=0,metadata=0x5
            actions=resubmit(,26)
        cookie=0x0, duration=5.399s, table=26, n_packets=6, n_bytes=508,
            idle_age=2, priority=100,metadata=0x5,
                dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
            actions=load:0xffff->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=5.398s, table=26, n_packets=0, n_bytes=0,
            idle_age=5, priority=50,metadata=0x5,dl_dst=fa:16:3e:d5:00:02
            actions=load:0x2->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=5.398s, table=26, n_packets=0, n_bytes=0,
            idle_age=5, priority=50,metadata=0x5,dl_dst=fa:16:3e:82:8b:0e
            actions=load:0x1->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=21.038s, table=32, n_packets=0, n_bytes=0,
            idle_age=21, priority=100,reg7=0x2,metadata=0x5
            actions=load:0x5->NXM_NX_TUN_ID[0..23],
                set_field:0x2/0xffffffff->tun_metadata0,
                move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:4
        cookie=0x0, duration=21.038s, table=32, n_packets=8, n_bytes=648,
            idle_age=11, priority=100,reg7=0xffff,metadata=0x5
            actions=load:0x5->NXM_NX_TUN_ID[0..23],
                set_field:0xffff/0xffffffff->tun_metadata0,
                move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],
                output:4,resubmit(,33)
        cookie=0x0, duration=5.397s, table=33, n_packets=12, n_bytes=1016,
            idle_age=2, priority=100,reg7=0xffff,metadata=0x5
            actions=load:0x1->NXM_NX_REG7[],resubmit(,34),
               load:0xffff->NXM_NX_REG7[]
        cookie=0x0, duration=5.397s, table=33, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,reg7=0x1,metadata=0x5
            actions=resubmit(,34)
        cookie=0x0, duration=21.074s, table=34, n_packets=8, n_bytes=648,
            idle_age=11, priority=100,reg6=0x1,reg7=0x1,metadata=0x5
            actions=drop
        cookie=0x0, duration=21.076s, table=48, n_packets=8, n_bytes=648,
            idle_age=11, priority=0,metadata=0x5 actions=resubmit(,49)
        cookie=0x0, duration=21.075s, table=49, n_packets=8, n_bytes=648,
            idle_age=11, priority=0,metadata=0x5 actions=resubmit(,50)
        cookie=0x0, duration=5.398s, table=50, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ipv6,reg0=0x1/0x1,metadata=0x5
            actions=ct(table=51,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=5.398s, table=50, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ip,reg0=0x1/0x1,metadata=0x5
            actions=ct(table=51,zone=NXM_NX_REG5[0..15])
        cookie=0x0, duration=5.398s, table=50, n_packets=6, n_bytes=508,
            idle_age=3, priority=0,metadata=0x5
            actions=resubmit(,51)
        cookie=0x0, duration=5.398s, table=51, n_packets=6, n_bytes=508,
            idle_age=3, priority=0,metadata=0x5
            actions=resubmit(,52)
        cookie=0x0, duration=5.398s, table=52, n_packets=6, n_bytes=508,
            idle_age=3, priority=0,metadata=0x5
            actions=resubmit(,53)
        cookie=0x0, duration=5.399s, table=53, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ipv6,reg0=0x4/0x4,metadata=0x5
            actions=ct(table=54,zone=NXM_NX_REG5[0..15],nat)
        cookie=0x0, duration=5.398s, table=53, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ip,reg0=0x4/0x4,metadata=0x5
            actions=ct(table=54,zone=NXM_NX_REG5[0..15],nat)
        cookie=0x0, duration=5.398s, table=53, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ip,reg0=0x2/0x2,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,54)
        cookie=0x0, duration=5.398s, table=53, n_packets=0, n_bytes=0,
            idle_age=5, priority=100,ipv6,reg0=0x2/0x2,metadata=0x5
            actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,54)
        cookie=0x0, duration=5.398s, table=53, n_packets=6, n_bytes=508,
            idle_age=3, priority=0,metadata=0x5
            actions=resubmit(,54)
        cookie=0x0, duration=5.398s, table=54, n_packets=6, n_bytes=508,
            idle_age=3, priority=0,metadata=0x5
            actions=resubmit(,55)
        cookie=0x0, duration=5.398s, table=55, n_packets=6, n_bytes=508,
            idle_age=3, priority=100,metadata=0x5,
                dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
            actions=resubmit(,64)
        cookie=0x0, duration=5.398s, table=55, n_packets=0, n_bytes=0,
            idle_age=5, priority=50,reg7=0x1,metadata=0x5
            actions=resubmit(,64)
        cookie=0x0, duration=5.398s, table=55, n_packets=0, n_bytes=0,
            idle_age=5, priority=50,reg7=0x2,metadata=0x5
            actions=resubmit(,64)
        cookie=0x0, duration=5.397s, table=64, n_packets=6, n_bytes=508,
            idle_age=3, priority=100,reg7=0x1,metadata=0x5
            actions=output:9
