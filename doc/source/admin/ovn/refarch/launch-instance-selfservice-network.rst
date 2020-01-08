.. _refarch-launch-instance-selfservice-network:

Launch an instance on a self-service network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To launch an instance on a self-service network, follow the same steps as
:ref:`launching an instance on the provider network
<refarch-launch-instance-provider-network>`, but using the UUID of the
self-service network.

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
launching an instance.

#. The OVN mechanism driver creates a logical port for the instance.

   .. code-block:: console

      _uuid               : c754d1d2-a7fb-4dd0-b14c-c076962b06b9
      addresses           : ["fa:16:3e:15:7d:13 192.168.1.5"]
      enabled             : true
      external_ids        : {"neutron:port_name"=""}
      name                : "eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"
      options             : {}
      parent_name         : []
      port_security       : ["fa:16:3e:15:7d:13 192.168.1.5"]
      tag                 : []
      type                : ""
      up                  : true

#. The OVN mechanism driver updates the appropriate Address Set object(s)
   with the address of the new instance:

   .. code-block:: console

      _uuid               : d0becdea-e1ed-48c4-9afc-e278cdef4629
      addresses           : ["192.168.1.5", "203.0.113.103"]
      external_ids        : {"neutron:security_group_name"=default}
      name                : "as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc"

#. The OVN mechanism driver creates ACL entries for this port and
   any other ports in the project.

   .. code-block:: console

      _uuid               : 00ecbe8f-c82a-4e18-b688-af2a1941cff7
      action              : allow
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && (ip4.dst == 255.255.255.255 || ip4.dst == 192.168.1.0/24) && udp && udp.src == 68 && udp.dst == 67"
      priority            : 1002

      _uuid               : 2bf5b7ed-008e-4676-bba5-71fe58897886
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4"
      priority            : 1002

      _uuid               : 330b4e27-074f-446a-849b-9ab0018b65c5
      action              : allow
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && ip4.src == 192.168.1.0/24 && udp && udp.src == 67 && udp.dst == 68"
      priority            : 1002

      _uuid               : 683f52f2-4be6-4bd7-a195-6c782daa7840
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip6"
      priority            : 1002

      _uuid               : 8160f0b4-b344-43d5-bbd4-ca63a71aa4fc
      action              : drop
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip"
      priority            : 1001

      _uuid               : 97c6b8ca-14ea-4812-8571-95d640a88f4f
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip6"
      priority            : 1002

      _uuid               : 9cfd8eb5-5daa-422e-8fe8-bd22fd7fa826
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && ip4.src == 0.0.0.0/0 && icmp4"
      priority            : 1002

      _uuid               : f72c2431-7a64-4cea-b84a-118bdc761be2
      action              : drop
      direction           : from-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "inport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip"
      priority            : 1001

      _uuid               : f94133fa-ed27-4d5e-a806-0d528e539cb3
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip4 && ip4.src == $as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc"
      priority            : 1002

      _uuid               : 7f7a92ff-b7e9-49b0-8be0-0dc388035df3
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="eaf36f62-5629-4ec4-b8b9-5e562c40e7ae"}
      log                 : false
      match               : "outport == \"eaf36f62-5629-4ec4-b8b9-5e562c40e7ae\" && ip6 && ip6.src == $as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc"
      priority            : 1002

#. The OVN mechanism driver updates the logical switch information with
   the UUIDs of these objects.

   .. code-block:: console

      _uuid               : 15e2c80b-1461-4003-9869-80416cd97de5
      acls                : [00ecbe8f-c82a-4e18-b688-af2a1941cff7,
                             2bf5b7ed-008e-4676-bba5-71fe58897886,
                             330b4e27-074f-446a-849b-9ab0018b65c5,
                             683f52f2-4be6-4bd7-a195-6c782daa7840,
                             7f7a92ff-b7e9-49b0-8be0-0dc388035df3,
                             8160f0b4-b344-43d5-bbd4-ca63a71aa4fc,
                             97c6b8ca-14ea-4812-8571-95d640a88f4f,
                             9cfd8eb5-5daa-422e-8fe8-bd22fd7fa826,
                             f72c2431-7a64-4cea-b84a-118bdc761be2,
                             f94133fa-ed27-4d5e-a806-0d528e539cb3]
      external_ids        : {"neutron:network_name"="selfservice"}
      name                : "neutron-6cc81cae-8c5f-4c09-aaf2-35d0aa95c084"
      ports               : [2df457a5-f71c-4a2f-b9ab-d9e488653872,
                             67c2737c-b380-492b-883b-438048b48e56,
                             c754d1d2-a7fb-4dd0-b14c-c076962b06b9]

#. With address sets, it is no longer necessary for the OVN mechanism
   driver to create separate ACLs for other instances in the project.
   That is handled automagically via address sets.

#. The OVN northbound service translates the updated Address Set object(s)
   into updated Address Set objects in the OVN southbound database:

   .. code-block:: console

      _uuid               : 2addbee3-7084-4fff-8f7b-15b1efebdaff
      addresses           : ["192.168.1.5", "203.0.113.103"]
      name                : "as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc"

#. The OVN northbound service adds a Port Binding for the new Logical
   Switch Port object:

   .. code-block:: console

      _uuid               : 7a558e7b-ed7a-424f-a0cf-ab67d2d832d7
      chassis             : b67d6da9-0222-4ab1-a852-ab2607610bf8
      datapath            : 3f6e16b5-a03a-48e5-9b60-7b7a0396c425
      logical_port        : "e9cb7857-4cb1-4e91-aae5-165a7ab5b387"
      mac                 : ["fa:16:3e:b6:91:70 192.168.1.5"]
      options             : {}
      parent_port         : []
      tag                 : []
      tunnel_key          : 3
      type                : ""

#. The OVN northbound service updates the flooding multicast group
   for the logical datapath with the new port binding:

   .. code-block:: console

      _uuid               : c08d0102-c414-4a47-98d9-dd3fa9f9901c
      datapath            : 0b214af6-8910-489c-926a-fd0ed16a8251
      name                : _MC_flood
      ports               : [3e463ca0-951c-46fd-b6cf-05392fa3aa1f,
                             794a6f03-7941-41ed-b1c6-0e00c1e18da0,
                             fa7b294d-2a62-45ae-8de3-a41c002de6de]
      tunnel_key          : 65535

#. The OVN northbound service adds Logical Flows based on the updated
   Address Set, ACL and Logical_Switch_Port objects:

   .. code-block:: console

      Datapath: 3f6e16b5-a03a-48e5-9b60-7b7a0396c425  Pipeline: ingress
        table= 0(  ls_in_port_sec_l2), priority=   50,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.src == {fa:16:3e:b6:a3:54}),
          action=(next;)
        table= 1(  ls_in_port_sec_ip), priority=   90,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.src == fa:16:3e:b6:a3:54 && ip4.src == 0.0.0.0 &&
            ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67),
          action=(next;)
        table= 1(  ls_in_port_sec_ip), priority=   90,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.src == fa:16:3e:b6:a3:54 && ip4.src == {192.168.1.5}),
          action=(next;)
        table= 1(  ls_in_port_sec_ip), priority=   80,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.src == fa:16:3e:b6:a3:54 && ip),
          action=(drop;)
        table= 2(  ls_in_port_sec_nd), priority=   90,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.src == fa:16:3e:b6:a3:54 && arp.sha == fa:16:3e:b6:a3:54 &&
            (arp.spa == 192.168.1.5 )),
          action=(next;)
        table= 2(  ls_in_port_sec_nd), priority=   80,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            (arp || nd)),
          action=(drop;)
        table= 3(      ls_in_pre_acl), priority=  110, match=(nd),
          action=(next;)
        table= 3(      ls_in_pre_acl), priority=  100, match=(ip),
          action=(reg0[0] = 1; next;)
        table= 6(          ls_in_acl), priority=65535,
          match=(!ct.est && ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 6(          ls_in_acl), priority=65535,
          match=(ct.est && !ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 6(          ls_in_acl), priority=65535, match=(ct.inv),
          action=(drop;)
        table= 6(          ls_in_acl), priority=65535, match=(nd),
          action=(next;)
        table= 6(          ls_in_acl), priority= 2002,
          match=(ct.new && (inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            ip6)),
          action=(reg0[1] = 1; next;)
        table= 6(          ls_in_acl), priority= 2002,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" && ip4 &&
            (ip4.dst == 255.255.255.255 || ip4.dst == 192.168.1.0/24) &&
            udp && udp.src == 68 && udp.dst == 67),
          action=(reg0[1] = 1; next;)
        table= 6(          ls_in_acl), priority= 2002,
          match=(ct.new && (inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            ip4)),
          action=(reg0[1] = 1; next;)
        table= 6(          ls_in_acl), priority= 2001,
          match=(inport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" && ip),
          action=(drop;)
        table= 6(          ls_in_acl), priority=    1, match=(ip),
          action=(reg0[1] = 1; next;)
        table= 9(   ls_in_arp_nd_rsp), priority=   50,
          match=(arp.tpa == 192.168.1.5 && arp.op == 1),
          action=(eth.dst = eth.src; eth.src = fa:16:3e:b6:a3:54; arp.op = 2; /* ARP reply */ arp.tha = arp.sha; arp.sha = fa:16:3e:b6:a3:54; arp.tpa = arp.spa; arp.spa = 192.168.1.5; outport = inport; inport = ""; /* Allow sending out inport. */ output;)
        table=10(      ls_in_l2_lkup), priority=   50,
          match=(eth.dst == fa:16:3e:b6:a3:54),
          action=(outport = "e9cb7857-4cb1-4e91-aae5-165a7ab5b387"; output;)
      Datapath: 3f6e16b5-a03a-48e5-9b60-7b7a0396c425  Pipeline: egress
        table= 1(     ls_out_pre_acl), priority=  110, match=(nd),
          action=(next;)
        table= 1(     ls_out_pre_acl), priority=  100, match=(ip),
          action=(reg0[0] = 1; next;)
        table= 4(         ls_out_acl), priority=65535, match=(nd),
          action=(next;)
        table= 4(         ls_out_acl), priority=65535,
          match=(!ct.est && ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 4(         ls_out_acl), priority=65535,
          match=(ct.est && !ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 4(         ls_out_acl), priority=65535, match=(ct.inv),
          action=(drop;)
        table= 4(         ls_out_acl), priority= 2002,
          match=(ct.new &&
            (outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" && ip6 &&
            ip6.src == $as_ip6_90a78a43_b549_4bee_8822_21fcccab58dc)),
          action=(reg0[1] = 1; next;)
        table= 4(         ls_out_acl), priority= 2002,
          match=(ct.new &&
            (outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" && ip4 &&
            ip4.src == $as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc)),
          action=(reg0[1] = 1; next;)
        table= 4(         ls_out_acl), priority= 2002,
          match=(outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" && ip4 &&
            ip4.src == 192.168.1.0/24 && udp && udp.src == 67 && udp.dst == 68),
          action=(reg0[1] = 1; next;)
        table= 4(         ls_out_acl), priority= 2001,
          match=(outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" && ip),
          action=(drop;)
        table= 4(         ls_out_acl), priority=    1, match=(ip),
          action=(reg0[1] = 1; next;)
        table= 6( ls_out_port_sec_ip), priority=   90,
          match=(outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.dst == fa:16:3e:b6:a3:54 &&
            ip4.dst == {255.255.255.255, 224.0.0.0/4, 192.168.1.5}),
          action=(next;)
        table= 6( ls_out_port_sec_ip), priority=   80,
          match=(outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.dst == fa:16:3e:b6:a3:54 && ip),
          action=(drop;)
        table= 7( ls_out_port_sec_l2), priority=   50,
          match=(outport == "e9cb7857-4cb1-4e91-aae5-165a7ab5b387" &&
            eth.dst == {fa:16:3e:b6:a3:54}),
          action=(output;)

#. The OVN controller service on each compute node translates these objects
   into flows on the integration bridge ``br-int``. Exact flows depend on
   whether the compute node containing the instance also contains a DHCP agent
   on the subnet.

   * On the compute node containing the instance, the Compute service creates
     a port that connects the instance to the integration bridge and OVN
     creates the following flows:

     .. code-block:: console

        # ovs-ofctl show br-int
        OFPT_FEATURES_REPLY (xid=0x2): dpid:000022024a1dc045
        n_tables:254, n_buffers:256
        capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
        actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
         12(tapeaf36f62-56): addr:fe:16:3e:15:7d:13
             config:     0
             state:      0
             current:    10MB-FD COPPER

     .. code-block:: console

        cookie=0x0, duration=179.460s, table=0, n_packets=122, n_bytes=10556,
            idle_age=1, priority=100,in_port=12
            actions=load:0x4->NXM_NX_REG5[],load:0x5->OXM_OF_METADATA[],
                load:0x3->NXM_NX_REG6[],resubmit(,16)
        cookie=0x0, duration=187.408s, table=16, n_packets=122, n_bytes=10556,
            idle_age=1, priority=50,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13
            actions=resubmit(,17)
        cookie=0x0, duration=187.408s, table=17, n_packets=2, n_bytes=684,
            idle_age=84, priority=90,udp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=0.0.0.0,nw_dst=255.255.255.255,
                tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=187.408s, table=17, n_packets=98, n_bytes=8276,
            idle_age=1, priority=90,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=192.168.1.5
            actions=resubmit(,18)
        cookie=0x0, duration=187.408s, table=17, n_packets=17, n_bytes=1386,
            idle_age=55, priority=80,ipv6,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=187.408s, table=17, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=187.408s, table=18, n_packets=5, n_bytes=210,
            idle_age=10, priority=90,arp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,arp_spa=192.168.1.5,
            arp_sha=fa:16:3e:15:7d:13
            actions=resubmit(,19)
        cookie=0x0, duration=187.408s, table=18, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=135,icmp_code=0
            actions=drop
        cookie=0x0, duration=187.408s, table=18, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=136,icmp_code=0
            actions=drop
        cookie=0x0, duration=187.408s, table=18, n_packets=0, n_bytes=0,
            idle_age=187, priority=80,arp,reg6=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=19, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=47.068s, table=19, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=47.068s, table=19, n_packets=33, n_bytes=4081,
            idle_age=0, priority=100,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=47.068s, table=19, n_packets=0, n_bytes=0,
            idle_age=47, priority=100,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=47.068s, table=22, n_packets=15, n_bytes=1392,
            idle_age=0, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,ct_state=+inv+trk,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,ct_state=+new+trk,ipv6,reg6=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=16, n_bytes=1922,
            idle_age=2, priority=2002,ct_state=+new+trk,ip,reg6=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=192.168.1.0/24,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.069s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2001,ipv6,reg6=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2001,ip,reg6=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=22, n_packets=2, n_bytes=767,
            idle_age=27, priority=1,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=1,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=179.457s, table=25, n_packets=2, n_bytes=84,
            idle_age=33, priority=50,arp,metadata=0x5,arp_tpa=192.168.1.5,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:15:7d:13,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e157d13->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a80105->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],
                load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=187.408s, table=26, n_packets=50, n_bytes=4806,
            idle_age=1, priority=50,metadata=0x5,dl_dst=fa:16:3e:15:7d:13
            actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=469.575s, table=33, n_packets=74, n_bytes=7040,
            idle_age=305, priority=100,reg7=0x4,metadata=0x4
            actions=load:0x1->NXM_NX_REG7[],resubmit(,33)
        cookie=0x0, duration=179.460s, table=34, n_packets=2, n_bytes=684,
            idle_age=84, priority=100,reg6=0x3,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.069s, table=49, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=47.068s, table=49, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=47.068s, table=49, n_packets=34, n_bytes=4455,
            idle_age=0, priority=100,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=47.068s, table=49, n_packets=0, n_bytes=0,
            idle_age=47, priority=100,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=47.069s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,ct_state=+inv+trk,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.069s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=22, n_bytes=2000,
            idle_age=0, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5
            actions=resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5
            actions=resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,ct_state=+new+trk,ip,reg7=0x3,
                metadata=0x5,nw_src=192.168.1.5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,ct_state=+new+trk,ip,reg7=0x3,
                metadata=0x5,nw_src=203.0.113.103
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=3, n_bytes=1141,
            idle_age=27, priority=2002,udp,reg7=0x3,metadata=0x5,
                nw_src=192.168.1.0/24,tp_src=67,tp_dst=68
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=39.497s, table=52, n_packets=0, n_bytes=0,
            idle_age=39, priority=2002,ct_state=+new+trk,ipv6,reg7=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=2001,ip,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=2001,ipv6,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=52, n_packets=9, n_bytes=1314,
            idle_age=2, priority=1,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=47.068s, table=52, n_packets=0, n_bytes=0,
            idle_age=47, priority=1,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=47.068s, table=54, n_packets=23, n_bytes=2945,
            idle_age=0, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=192.168.1.11
            actions=resubmit(,55)
        cookie=0x0, duration=47.068s, table=54, n_packets=0, n_bytes=0,
            idle_age=47, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=255.255.255.255
            actions=resubmit(,55)
        cookie=0x0, duration=47.068s, table=54, n_packets=0, n_bytes=0,
            idle_age=47, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=224.0.0.0/4
            actions=resubmit(,55)
        cookie=0x0, duration=47.068s, table=54, n_packets=0, n_bytes=0,
            idle_age=47, priority=80,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=47.068s, table=54, n_packets=0, n_bytes=0,
            idle_age=47, priority=80,ipv6,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=47.068s, table=55, n_packets=25, n_bytes=3029,
            idle_age=0, priority=50,reg7=0x3,metadata=0x7,
                dl_dst=fa:16:3e:15:7d:13
            actions=resubmit(,64)
        cookie=0x0, duration=179.460s, table=64, n_packets=116, n_bytes=10623,
            idle_age=1, priority=100,reg7=0x3,metadata=0x5
            actions=output:12

   * For each compute node that only contains a DHCP agent on the subnet,
     OVN creates the following flows:

     .. code-block:: console

        cookie=0x0, duration=192.587s, table=16, n_packets=0, n_bytes=0,
            idle_age=192, priority=50,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13
            actions=resubmit(,17)
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=192.168.1.5
            actions=resubmit(,18)
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,udp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,nw_src=0.0.0.0,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ipv6,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=192.587s, table=17, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ip,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,arp,reg6=0x3,metadata=0x5,
                dl_src=fa:16:3e:15:7d:13,arp_spa=192.168.1.5,
                arp_sha=fa:16:3e:15:7d:13
            actions=resubmit(,19)
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,arp,reg6=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=135,icmp_code=0
            actions=drop
        cookie=0x0, duration=192.587s, table=18, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,icmp6,reg6=0x3,metadata=0x5,
                icmp_type=136,icmp_code=0
            actions=drop
        cookie=0x0, duration=47.068s, table=19, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=47.068s, table=19, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=47.068s, table=19, n_packets=33, n_bytes=4081,
            idle_age=0, priority=100,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=47.068s, table=19, n_packets=0, n_bytes=0,
            idle_age=47, priority=100,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=47.068s, table=22, n_packets=15, n_bytes=1392,
            idle_age=0, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=65535,ct_state=+inv+trk,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,ct_state=+new+trk,ipv6,reg6=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=16, n_bytes=1922,
            idle_age=2, priority=2002,ct_state=+new+trk,ip,reg6=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2002,udp,reg6=0x3,metadata=0x5,
                nw_dst=192.168.1.0/24,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.069s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2001,ipv6,reg6=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=2001,ip,reg6=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=47.068s, table=22, n_packets=2, n_bytes=767,
            idle_age=27, priority=1,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=47.068s, table=22, n_packets=0, n_bytes=0,
            idle_age=47, priority=1,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=179.457s, table=25, n_packets=2, n_bytes=84,
            idle_age=33, priority=50,arp,metadata=0x5,arp_tpa=192.168.1.5,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:15:7d:13,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163e157d13->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a80105->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],
                load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=192.587s, table=26, n_packets=61, n_bytes=5607,
            idle_age=6, priority=50,metadata=0x5,dl_dst=fa:16:3e:15:7d:13
            actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=184.640s, table=32, n_packets=61, n_bytes=5607,
            idle_age=6, priority=100,reg7=0x3,metadata=0x5
            actions=load:0x5->NXM_NX_TUN_ID[0..23],
                set_field:0x3/0xffffffff->tun_metadata0,
                move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:4
        cookie=0x0, duration=47.069s, table=49, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=135,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=47.068s, table=49, n_packets=0, n_bytes=0,
            idle_age=47, priority=110,icmp6,metadata=0x5,icmp_type=136,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=47.068s, table=49, n_packets=34, n_bytes=4455,
            idle_age=0, priority=100,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=47.068s, table=49, n_packets=0, n_bytes=0,
            idle_age=47, priority=100,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=65535,ct_state=+inv+trk,
                metadata=0x5
            actions=drop
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x5
            actions=resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=27, n_bytes=2316,
            idle_age=6, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x5
            actions=resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,icmp,reg7=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,ipv6,reg7=0x3,
                metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,udp,reg7=0x3,metadata=0x5,
                nw_src=192.168.1.0/24,tp_src=67,tp_dst=68
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=2002,ct_state=+new+trk,ip,reg7=0x3,
                metadata=0x5,nw_src=203.0.113.103
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,50)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=2001,ip,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=2001,ipv6,reg7=0x3,metadata=0x5
            actions=drop
        cookie=0x0, duration=192.587s, table=52, n_packets=25, n_bytes=2604,
            idle_age=6, priority=1,ip,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=192.587s, table=52, n_packets=0, n_bytes=0,
            idle_age=192, priority=1,ipv6,metadata=0x5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=192.587s, table=54, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=224.0.0.0/4
            actions=resubmit(,55)
        cookie=0x0, duration=192.587s, table=54, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=255.255.255.255
            actions=resubmit(,55)
        cookie=0x0, duration=192.587s, table=54, n_packets=0, n_bytes=0,
            idle_age=192, priority=90,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13,nw_dst=192.168.1.5
            actions=resubmit(,55)
        cookie=0x0, duration=192.587s, table=54, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ipv6,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=192.587s, table=54, n_packets=0, n_bytes=0,
            idle_age=192, priority=80,ip,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13
            actions=drop
        cookie=0x0, duration=192.587s, table=55, n_packets=0, n_bytes=0,
            idle_age=192, priority=50,reg7=0x3,metadata=0x5,
                dl_dst=fa:16:3e:15:7d:13
            actions=resubmit(,64)

   * For each compute node that contains neither the instance nor a DHCP
     agent on the subnet, OVN creates the following flows:

     .. code-block:: console

        cookie=0x0, duration=189.763s, table=52, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,ct_state=+new+trk,ipv6,reg7=0x4,
                metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=189.763s, table=52, n_packets=0, n_bytes=0,
            idle_age=189, priority=2002,ct_state=+new+trk,ip,reg7=0x4,
                metadata=0x4,nw_src=192.168.1.5
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
