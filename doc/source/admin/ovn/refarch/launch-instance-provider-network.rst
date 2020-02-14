.. _refarch-launch-instance-provider-network:

Launch an instance on a provider network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. On the controller node, source the credentials for a regular
   (non-privileged) project. The following example uses the ``demo``
   project.

#. On the controller node, launch an instance using the UUID of the
   provider network.

   .. code-block:: console

      $ openstack server create --flavor m1.tiny --image cirros \
        --nic net-id=0243277b-4aa8-46d8-9e10-5c9ad5e01521 \
        --security-group default --key-name mykey provider-instance
      +--------------------------------------+-----------------------------------------------+
      | Property                             | Value                                         |
      +--------------------------------------+-----------------------------------------------+
      | OS-DCF:diskConfig                    | MANUAL                                        |
      | OS-EXT-AZ:availability_zone          | nova                                          |
      | OS-EXT-STS:power_state               | 0                                             |
      | OS-EXT-STS:task_state                | scheduling                                    |
      | OS-EXT-STS:vm_state                  | building                                      |
      | OS-SRV-USG:launched_at               | -                                             |
      | OS-SRV-USG:terminated_at             | -                                             |
      | accessIPv4                           |                                               |
      | accessIPv6                           |                                               |
      | adminPass                            | hdF4LMQqC5PB                                  |
      | config_drive                         |                                               |
      | created                              | 2015-09-17T21:58:18Z                          |
      | flavor                               | m1.tiny (1)                                   |
      | hostId                               |                                               |
      | id                                   | 181c52ba-aebc-4c32-a97d-2e8e82e4eaaf          |
      | image                                | cirros (38047887-61a7-41ea-9b49-27987d5e8bb9) |
      | key_name                             | mykey                                         |
      | metadata                             | {}                                            |
      | name                                 | provider-instance                             |
      | os-extended-volumes:volumes_attached | []                                            |
      | progress                             | 0                                             |
      | security_groups                      | default                                       |
      | status                               | BUILD                                         |
      | tenant_id                            | f5b2ccaa75ac413591f12fcaa096aa5c              |
      | updated                              | 2015-09-17T21:58:18Z                          |
      | user_id                              | 684286a9079845359882afc3aa5011fb              |
      +--------------------------------------+-----------------------------------------------+

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
launching an instance.

#. The OVN mechanism driver creates a logical port for the instance.

   .. code-block:: console

      _uuid               : cc891503-1259-47a1-9349-1c0293876664
      addresses           : ["fa:16:3e:1c:ca:6a 203.0.113.103"]
      enabled             : true
      external_ids        : {"neutron:port_name"=""}
      name                : "cafd4862-c69c-46e4-b3d2-6141ce06b205"
      options             : {}
      parent_name         : []
      port_security       : ["fa:16:3e:1c:ca:6a 203.0.113.103"]
      tag                 : []
      type                : ""
      up                  : true

#. The OVN mechanism driver updates the appropriate Address Set
   entry with the address of this instance:

   .. code-block:: console

      _uuid               : d0becdea-e1ed-48c4-9afc-e278cdef4629
      addresses           : ["203.0.113.103"]
      external_ids        : {"neutron:security_group_name"=default}
      name                : "as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc"

#. The OVN mechanism driver creates ACL entries for this port and
   any other ports in the project.

   .. code-block:: console

      _uuid               : f8d27bfc-4d74-4e73-8fac-c84585443efd
      action              : drop
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip"
      priority            : 1001

      _uuid               : a61d0068-b1aa-4900-9882-e0671d1fc131
      action              : allow
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && ip4.src == 203.0.113.0/24 && udp && udp.src == 67 && udp.dst == 68"
      priority            : 1002

      _uuid               : a5a787b8-7040-4b63-a20a-551bd73eb3d1
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip6"
      priority            : 1002

      _uuid               : 7b3f63b8-e69a-476c-ad3d-37de043232b2
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && ip4.src = $as_ip4_90a78a43_b5649_4bee_8822_21fcccab58dc"
      priority            : 1002

      _uuid               : 36dbb1b1-cd30-4454-a0bf-923646eb7c3f
      action              : allow
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4 && (ip4.dst == 255.255.255.255 || ip4.dst == 203.0.113.0/24) && udp && udp.src == 68 && udp.dst == 67"
      priority            : 1002

      _uuid               : 05a92f66-be48-461e-a7f1-b07bfbd3e667
      action              : allow-related
      direction           : from-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "inport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip4"
      priority            : 1002

      _uuid               : 37f18377-d6c3-4c44-9e4d-2170710e50ff
      action              : drop
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip"
      priority            : 1001

      _uuid               : 6d4db3cf-c1f1-4006-ad66-ae582a6acd21
      action              : allow-related
      direction           : to-lport
      external_ids        : {"neutron:lport"="cafd4862-c69c-46e4-b3d2-6141ce06b205"}
      log                 : false
      match               : "outport == \"cafd4862-c69c-46e4-b3d2-6141ce06b205\" && ip6 && ip6.src = $as_ip6_90a78a43_b5649_4bee_8822_21fcccab58dc"
      priority            : 1002

#. The OVN mechanism driver updates the logical switch information with
   the UUIDs of these objects.

   .. code-block:: console

      _uuid               : 924500c4-8580-4d5f-a7ad-8769f6e58ff5
      acls                : [05a92f66-be48-461e-a7f1-b07bfbd3e667,
                             36dbb1b1-cd30-4454-a0bf-923646eb7c3f,
                             37f18377-d6c3-4c44-9e4d-2170710e50ff,
                             7b3f63b8-e69a-476c-ad3d-37de043232b2,
                             a5a787b8-7040-4b63-a20a-551bd73eb3d1,
                             a61d0068-b1aa-4900-9882-e0671d1fc131,
                             f8d27bfc-4d74-4e73-8fac-c84585443efd]
      external_ids        : {"neutron:network_name"=provider}
      name                : "neutron-670efade-7cd0-4d87-8a04-27f366eb8941"
      ports               : [38cf8b52-47c4-4e93-be8d-06bf71f6a7c9,
                             5e144ab9-3e08-4910-b936-869bbbf254c8,
                             a576b812-9c3e-4cfb-9752-5d8500b3adf9,
                             cc891503-1259-47a1-9349-1c0293876664]

#. The OVN northbound service creates port bindings for the logical
   ports and adds them to the appropriate multicast group.

   * Port bindings

     .. code-block:: console

        _uuid               : e73e3fcd-316a-4418-bbd5-a8a42032b1c3
        chassis             : fc5ab9e7-bc28-40e8-ad52-2949358cc088
        datapath            : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
        logical_port        : "cafd4862-c69c-46e4-b3d2-6141ce06b205"
        mac                 : ["fa:16:3e:1c:ca:6a 203.0.113.103"]
        options             : {}
        parent_port         : []
        tag                 : []
        tunnel_key          : 4
        type                : ""

   * Multicast groups

     .. code-block:: console

        _uuid               : 39b32ccd-fa49-4046-9527-13318842461e
        datapath            : bd0ab2b3-4cf4-4289-9529-ef430f6a89e6
        name                : _MC_flood
        ports               : [030024f4-61c3-4807-859b-07727447c427,
                               904c3108-234d-41c0-b93c-116b7e352a75,
                               cc5bcd19-bcae-4e29-8cee-3ec8a8a75d46,
                               e73e3fcd-316a-4418-bbd5-a8a42032b1c3]
        tunnel_key          : 65535

#. The OVN northbound service translates the Address Set change into
   the new Address Set in the OVN southbound database.

   .. code-block:: console

      _uuid               : 2addbee3-7084-4fff-8f7b-15b1efebdaff
      addresses           : ["203.0.113.103"]
      name                : "as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc"

#. The OVN northbound service translates the ACL and logical port objects
   into logical flows in the OVN southbound database.

   .. code-block:: console

      Datapath: bd0ab2b3-4cf4-4289-9529-ef430f6a89e6  Pipeline: ingress
        table= 0(  ls_in_port_sec_l2), priority=   50,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.src == {fa:16:3e:1c:ca:6a}),
          action=(next;)
        table= 1(  ls_in_port_sec_ip), priority=   90,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.src == fa:16:3e:1c:ca:6a && ip4.src == {203.0.113.103}),
          action=(next;)
        table= 1(  ls_in_port_sec_ip), priority=   90,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.src == fa:16:3e:1c:ca:6a && ip4.src == 0.0.0.0 &&
                 ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67),
          action=(next;)
        table= 1(  ls_in_port_sec_ip), priority=   80,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.src == fa:16:3e:1c:ca:6a && ip),
          action=(drop;)
        table= 2(  ls_in_port_sec_nd), priority=   90,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.src == fa:16:3e:1c:ca:6a &&
                 arp.sha == fa:16:3e:1c:ca:6a && (arp.spa == 203.0.113.103 )),
          action=(next;)
        table= 2(  ls_in_port_sec_nd), priority=   80,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 (arp || nd)),
          action=(drop;)
        table= 3(      ls_in_pre_acl), priority=  110,
          match=(nd),
          action=(next;)
        table= 3(      ls_in_pre_acl), priority=  100,
          match=(ip),
          action=(reg0[0] = 1; next;)
        table= 6(          ls_in_acl), priority=65535,
          match=(ct.inv),
          action=(drop;)
        table= 6(          ls_in_acl), priority=65535,
          match=(nd),
          action=(next;)
        table= 6(          ls_in_acl), priority=65535,
          match=(ct.est && !ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 6(          ls_in_acl), priority=65535,
          match=(!ct.est && ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 6(          ls_in_acl), priority= 2002,
          match=(ct.new && (inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205"
                 && ip6)),
          action=(reg0[1] = 1; next;)
        table= 6(          ls_in_acl), priority= 2002,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" && ip4 &&
                 (ip4.dst == 255.255.255.255 || ip4.dst == 203.0.113.0/24) &&
                 udp && udp.src == 68 && udp.dst == 67),
          action=(reg0[1] = 1; next;)
        table= 6(          ls_in_acl), priority= 2002,
          match=(ct.new && (inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 ip4)),
          action=(reg0[1] = 1; next;)
        table= 6(          ls_in_acl), priority= 2001,
          match=(inport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" && ip),
          action=(drop;)
        table= 6(          ls_in_acl), priority=    1,
          match=(ip),
          action=(reg0[1] = 1; next;)
        table= 9(      ls_in_arp_rsp), priority=   50,
          match=(arp.tpa == 203.0.113.103 && arp.op == 1),
          action=(eth.dst = eth.src; eth.src = fa:16:3e:1c:ca:6a;
                  arp.op = 2; /* ARP reply */ arp.tha = arp.sha;
                  arp.sha = fa:16:3e:1c:ca:6a; arp.tpa = arp.spa;
                  arp.spa = 203.0.113.103; outport = inport;
                  inport = ""; /* Allow sending out inport. */ output;)
        table=10(      ls_in_l2_lkup), priority=   50,
          match=(eth.dst == fa:16:3e:1c:ca:6a),
          action=(outport = "cafd4862-c69c-46e4-b3d2-6141ce06b205"; output;)
      Datapath: bd0ab2b3-4cf4-4289-9529-ef430f6a89e6  Pipeline: egress
        table= 1(     ls_out_pre_acl), priority=  110,
          match=(nd),
          action=(next;)
        table= 1(     ls_out_pre_acl), priority=  100,
          match=(ip),
          action=(reg0[0] = 1; next;)
        table= 4(         ls_out_acl), priority=65535,
          match=(!ct.est && ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 4(         ls_out_acl), priority=65535,
          match=(ct.est && !ct.rel && !ct.new && !ct.inv),
          action=(next;)
        table= 4(         ls_out_acl), priority=65535,
          match=(ct.inv),
          action=(drop;)
        table= 4(         ls_out_acl), priority=65535,
          match=(nd),
          action=(next;)
        table= 4(         ls_out_acl), priority= 2002,
          match=(ct.new &&
                 (outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" && ip6 &&
                  ip6.src == $as_ip6_90a78a43_b549_4bee_8822_21fcccab58dc)),
          action=(reg0[1] = 1; next;)
        table= 4(         ls_out_acl), priority= 2002,
          match=(ct.new &&
                 (outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" && ip4 &&
                  ip4.src == $as_ip4_90a78a43_b549_4bee_8822_21fcccab58dc)),
          action=(reg0[1] = 1; next;)
        table= 4(         ls_out_acl), priority= 2002,
          match=(outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" && ip4 &&
                 ip4.src == 203.0.113.0/24 && udp && udp.src == 67 &&
                 udp.dst == 68),
          action=(reg0[1] = 1; next;)
        table= 4(         ls_out_acl), priority= 2001,
          match=(outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" && ip),
          action=(drop;)
        table= 4(         ls_out_acl), priority=    1,
          match=(ip),
          action=(reg0[1] = 1; next;)
        table= 6( ls_out_port_sec_ip), priority=   90,
          match=(outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.dst == fa:16:3e:1c:ca:6a &&
                 ip4.dst == {255.255.255.255, 224.0.0.0/4, 203.0.113.103}),
          action=(next;)
        table= 6( ls_out_port_sec_ip), priority=   80,
          match=(outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.dst == fa:16:3e:1c:ca:6a && ip),
          action=(drop;)
        table= 7( ls_out_port_sec_l2), priority=   50,
          match=(outport == "cafd4862-c69c-46e4-b3d2-6141ce06b205" &&
                 eth.dst == {fa:16:3e:1c:ca:6a}),
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
         9(tapcafd4862-c6): addr:fe:16:3e:1c:ca:6a
             config:     0
             state:      0
             current:    10MB-FD COPPER
             speed: 10 Mbps now, 0 Mbps max

     .. code-block:: console

        cookie=0x0, duration=184.992s, table=0, n_packets=175, n_bytes=15270,
            idle_age=15, priority=100,in_port=9
            actions=load:0x3->NXM_NX_REG5[],load:0x4->OXM_OF_METADATA[],
                load:0x4->NXM_NX_REG6[],resubmit(,16)
        cookie=0x0, duration=191.687s, table=16, n_packets=175, n_bytes=15270,
            idle_age=15, priority=50,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a
            actions=resubmit(,17)
        cookie=0x0, duration=191.687s, table=17, n_packets=2, n_bytes=684,
            idle_age=112, priority=90,udp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=0.0.0.0,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=191.687s, table=17, n_packets=146, n_bytes=12780,
            idle_age=20, priority=90,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=203.0.113.103
            actions=resubmit(,18)
        cookie=0x0, duration=191.687s, table=17, n_packets=17, n_bytes=1386,
            idle_age=92, priority=80,ipv6,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=191.687s, table=17, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=191.687s, table=18, n_packets=10, n_bytes=420,
            idle_age=15, priority=90,arp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,arp_spa=203.0.113.103,
                arp_sha=fa:16:3e:1c:ca:6a
            actions=resubmit(,19)
        cookie=0x0, duration=191.687s, table=18, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=136,icmp_code=0
            actions=drop
        cookie=0x0, duration=191.687s, table=18, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=135,icmp_code=0
            actions=drop
        cookie=0x0, duration=191.687s, table=18, n_packets=0, n_bytes=0,
            idle_age=191, priority=80,arp,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.033s, table=19, n_packets=0, n_bytes=0,
            idle_age=75, priority=110,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=75.032s, table=19, n_packets=0, n_bytes=0,
            idle_age=75, priority=110,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=75.032s, table=19, n_packets=34, n_bytes=5170,
            idle_age=49, priority=100,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=75.032s, table=19, n_packets=0, n_bytes=0,
            idle_age=75, priority=100,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=13, n_bytes=1118,
            idle_age=49, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4
            actions=resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4
            actions=resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.033s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=2002,ct_state=+new+trk,ipv6,reg6=0x4,
                metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=15, n_bytes=1816,
            idle_age=49, priority=2002,ct_state=+new+trk,ip,reg6=0x4,
                metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=203.0.113.0/24,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=75.033s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=2001,ip,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=2001,ipv6,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.032s, table=22, n_packets=6, n_bytes=2236,
            idle_age=54, priority=1,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=75.032s, table=22, n_packets=0, n_bytes=0,
            idle_age=75, priority=1,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=67.064s, table=25, n_packets=0, n_bytes=0,
            idle_age=67, priority=50,arp,metadata=0x4,arp_tpa=203.0.113.103,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:1c:ca:6a,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163ed63dca->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a81268->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
                load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=75.033s, table=26, n_packets=19, n_bytes=2776,
            idle_age=44, priority=50,metadata=0x4,dl_dst=fa:16:3e:1c:ca:6a
            actions=load:0x4->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=221031.310s, table=33, n_packets=72, n_bytes=6292,
            idle_age=20, hard_age=65534, priority=100,reg7=0x3,metadata=0x4
            actions=load:0x1->NXM_NX_REG7[],resubmit(,33)
        cookie=0x0, duration=184.992s, table=34, n_packets=2, n_bytes=684,
            idle_age=112, priority=100,reg6=0x4,reg7=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.034s, table=49, n_packets=0, n_bytes=0,
            idle_age=75, priority=110,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=75.033s, table=49, n_packets=0, n_bytes=0,
            idle_age=75, priority=110,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=75.033s, table=49, n_packets=38, n_bytes=6566,
            idle_age=49, priority=100,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=75.033s, table=49, n_packets=0, n_bytes=0,
            idle_age=75, priority=100,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=75.033s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4
            actions=resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=13, n_bytes=1118,
            idle_age=49, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4
            actions=resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.034s, table=52, n_packets=4, n_bytes=1538,
            idle_age=54, priority=2002,udp,reg7=0x4,metadata=0x4,
                nw_src=203.0.113.0/24,tp_src=67,tp_dst=68
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=2002,ct_state=+new+trk,ip,reg7=0x4,
                metadata=0x4,nw_src=203.0.113.103
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=2.041s, table=52, n_packets=0, n_bytes=0,
            idle_age=2, priority=2002,ct_state=+new+trk,ipv6,reg7=0x4,
                metadata=0x4,ipv6_src=::2/::2
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=2, n_bytes=698,
            idle_age=54, priority=2001,ip,reg7=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.033s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=2001,ipv6,reg7=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=75.034s, table=52, n_packets=0, n_bytes=0,
            idle_age=75, priority=1,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=75.033s, table=52, n_packets=19, n_bytes=3212,
            idle_age=49, priority=1,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=75.034s, table=54, n_packets=17, n_bytes=2656,
            idle_age=49, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=203.0.113.103
            actions=resubmit(,55)
        cookie=0x0, duration=75.033s, table=54, n_packets=0, n_bytes=0,
            idle_age=75, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=255.255.255.255
            actions=resubmit(,55)
        cookie=0x0, duration=75.033s, table=54, n_packets=0, n_bytes=0,
            idle_age=75, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=224.0.0.0/4
            actions=resubmit(,55)
        cookie=0x0, duration=75.033s, table=54, n_packets=0, n_bytes=0,
            idle_age=75, priority=80,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=75.033s, table=54, n_packets=0, n_bytes=0,
            idle_age=75, priority=80,ipv6,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=75.033s, table=55, n_packets=21, n_bytes=2860,
            idle_age=44, priority=50,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a
            actions=resubmit(,64)
        cookie=0x0, duration=184.992s, table=64, n_packets=166, n_bytes=15088,
            idle_age=15, priority=100,reg7=0x4,metadata=0x4
            actions=output:9

   * For each compute node that only contains a DHCP agent on the subnet, OVN
     creates the following flows:

     .. code-block:: console

        cookie=0x0, duration=189.649s, table=16, n_packets=0, n_bytes=0,
            idle_age=189, priority=50,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a
            actions=resubmit(,17)
        cookie=0x0, duration=189.650s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,udp,reg6=0x4,metadata=0x4,
                dl_src=fa:14:3e:1c:ca:6a,nw_src=0.0.0.0,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=resubmit(,18)
        cookie=0x0, duration=189.649s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,nw_src=203.0.113.103
            actions=resubmit(,18)
        cookie=0x0, duration=189.650s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,ipv6,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=189.650s, table=17, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,ip,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=189.650s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=90,arp,reg6=0x4,metadata=0x4,
                dl_src=fa:16:3e:1c:ca:6a,arp_spa=203.0.113.103,
                arp_sha=fa:16:3e:1c:ca:6a
            actions=resubmit(,19)
        cookie=0x0, duration=189.650s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=136,icmp_code=0
            actions=drop
        cookie=0x0, duration=189.650s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,icmp6,reg6=0x4,metadata=0x4,
                icmp_type=135,icmp_code=0
            actions=drop
        cookie=0x0, duration=189.649s, table=18, n_packets=0, n_bytes=0,
            idle_age=189, priority=80,arp,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.452s, table=19, n_packets=0, n_bytes=0,
            idle_age=79, priority=110,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=79.450s, table=19, n_packets=0, n_bytes=0,
            idle_age=79, priority=110,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,20)
        cookie=0x0, duration=79.452s, table=19, n_packets=0, n_bytes=0,
            idle_age=79, priority=100,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=79.450s, table=19, n_packets=18, n_bytes=3164,
            idle_age=57, priority=100,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
        cookie=0x0, duration=79.450s, table=22, n_packets=6, n_bytes=510,
            idle_age=57, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4
            actions=resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4
            actions=resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.453s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=2002,ct_state=+new+trk,ipv6,reg6=0x4,
                metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=2002,ct_state=+new+trk,ip,reg6=0x4,
                metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=203.0.113.0/24,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=2002,udp,reg6=0x4,metadata=0x4,
                nw_dst=255.255.255.255,tp_src=68,tp_dst=67
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=79.452s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=2001,ip,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=2001,ipv6,reg6=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.450s, table=22, n_packets=0, n_bytes=0,
            idle_age=79, priority=1,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=79.450s, table=22, n_packets=12, n_bytes=2654,
            idle_age=57, priority=1,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
        cookie=0x0, duration=71.483s, table=25, n_packets=0, n_bytes=0,
            idle_age=71, priority=50,arp,metadata=0x4,arp_tpa=203.0.113.103,
                arp_op=1
            actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
                mod_dl_src:fa:16:3e:1c:ca:6a,load:0x2->NXM_OF_ARP_OP[],
                move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
                load:0xfa163ed63dca->NXM_NX_ARP_SHA[],
                move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
                load:0xc0a81268->NXM_OF_ARP_SPA[],
                move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
                load:0->NXM_OF_IN_PORT[],resubmit(,32)
        cookie=0x0, duration=79.450s, table=26, n_packets=8, n_bytes=1258,
            idle_age=57, priority=50,metadata=0x4,dl_dst=fa:16:3e:1c:ca:6a
            actions=load:0x4->NXM_NX_REG7[],resubmit(,32)
        cookie=0x0, duration=182.952s, table=33, n_packets=74, n_bytes=7040,
            idle_age=18, priority=100,reg7=0x4,metadata=0x4
            actions=load:0x1->NXM_NX_REG7[],resubmit(,33)
        cookie=0x0, duration=79.451s, table=49, n_packets=0, n_bytes=0,
            idle_age=79, priority=110,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=79.450s, table=49, n_packets=0, n_bytes=0,
            idle_age=79, priority=110,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,50)
        cookie=0x0, duration=79.450s, table=49, n_packets=18, n_bytes=3164,
            idle_age=57, priority=100,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=79.450s, table=49, n_packets=0, n_bytes=0,
            idle_age=79, priority=100,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,ct_state=-new-est+rel-inv+trk,
                metadata=0x4
            actions=resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=6, n_bytes=510,
            idle_age=57, priority=65535,ct_state=-new+est-rel-inv+trk,
                metadata=0x4
            actions=resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,icmp6,metadata=0x4,icmp_type=135,
                icmp_code=0
            actions=resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,icmp6,metadata=0x4,icmp_type=136,
                icmp_code=0
            actions=resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=65535,ct_state=+inv+trk,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.452s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=2002,udp,reg7=0x4,metadata=0x4,
                nw_src=203.0.113.0/24,tp_src=67,tp_dst=68
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=2002,ct_state=+new+trk,ip,reg7=0x4,
                metadata=0x4,nw_src=203.0.113.103
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=71.483s, table=52, n_packets=0, n_bytes=0,
            idle_age=71, priority=2002,ct_state=+new+trk,ipv6,reg7=0x4,
                metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=2001,ipv6,reg7=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.450s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=2001,ip,reg7=0x4,metadata=0x4
            actions=drop
        cookie=0x0, duration=79.453s, table=52, n_packets=0, n_bytes=0,
            idle_age=79, priority=1,ipv6,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=79.450s, table=52, n_packets=12, n_bytes=2654,
            idle_age=57, priority=1,ip,metadata=0x4
            actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
        cookie=0x0, duration=79.452s, table=54, n_packets=0, n_bytes=0,
            idle_age=79, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=255.255.255.255
            actions=resubmit(,55)
        cookie=0x0, duration=79.452s, table=54, n_packets=0, n_bytes=0,
            idle_age=79, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=203.0.113.103
            actions=resubmit(,55)
        cookie=0x0, duration=79.452s, table=54, n_packets=0, n_bytes=0,
            idle_age=79, priority=90,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a,nw_dst=224.0.0.0/4
            actions=resubmit(,55)
        cookie=0x0, duration=79.450s, table=54, n_packets=0, n_bytes=0,
            idle_age=79, priority=80,ip,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=79.450s, table=54, n_packets=0, n_bytes=0,
            idle_age=79, priority=80,ipv6,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a
            actions=drop
        cookie=0x0, duration=79.450s, table=55, n_packets=0, n_bytes=0,
            idle_age=79, priority=50,reg7=0x4,metadata=0x4,
                dl_dst=fa:16:3e:1c:ca:6a
            actions=resubmit(,64)
