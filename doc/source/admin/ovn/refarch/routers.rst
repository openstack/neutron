.. _refarch-routers:

Routers
-------

Routers pass traffic between layer-3 networks.

Create a router
~~~~~~~~~~~~~~~

#. On the controller node, source the credentials for a regular
   (non-privileged) project. The following example uses the ``demo``
   project.

#. On the controller node, create router in the Networking service.

   .. code-block:: console

      $ openstack router create router
      +-----------------------+--------------------------------------+
      | Field                 | Value                                |
      +-----------------------+--------------------------------------+
      | admin_state_up        | UP                                   |
      | description           |                                      |
      | external_gateway_info | null                                 |
      | headers               |                                      |
      | id                    | 24addfcd-5506-405d-a59f-003644c3d16a |
      | name                  | router                               |
      | project_id            | b1ebf33664df402693f729090cfab861     |
      | routes                |                                      |
      | status                | ACTIVE                               |
      +-----------------------+--------------------------------------+

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
creating a router.

#. The OVN mechanism driver translates the router into a logical
   router object in the OVN northbound database.

   .. code-block:: console

      _uuid               : 1c2e340d-dac9-496b-9e86-1065f9dab752
      default_gw          : []
      enabled             : []
      external_ids        : {"neutron:router_name"="router"}
      name                : "neutron-a24fd760-1a99-4eec-9f02-24bb284ff708"
      ports               : []
      static_routes       : []

#. The OVN northbound service translates this object into logical flows
   and datapath bindings in the OVN southbound database.

   * Datapath bindings

     .. code-block:: console

        _uuid               : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        external_ids        : {logical-router="1c2e340d-dac9-496b-9e86-1065f9dab752"}
        tunnel_key          : 3

   * Logical flows

     .. code-block:: console

        Datapath: 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa  Pipeline: ingress
          table= 0(    lr_in_admission), priority=  100,
            match=(vlan.present || eth.src[40]),
            action=(drop;)
          table= 1(     lr_in_ip_input), priority=  100,
            match=(ip4.mcast || ip4.src == 255.255.255.255 ||
                   ip4.src == 127.0.0.0/8 || ip4.dst == 127.0.0.0/8 ||
                   ip4.src == 0.0.0.0/8 || ip4.dst == 0.0.0.0/8),
            action=(drop;)
          table= 1(     lr_in_ip_input), priority=   50, match=(ip4.mcast),
            action=(drop;)
          table= 1(     lr_in_ip_input), priority=   50, match=(eth.bcast),
            action=(drop;)
          table= 1(     lr_in_ip_input), priority=   30,
            match=(ip4 && ip.ttl == {0, 1}), action=(drop;)
          table= 1(     lr_in_ip_input), priority=    0, match=(1),
            action=(next;)
          table= 2(       lr_in_unsnat), priority=    0, match=(1),
            action=(next;)
          table= 3(         lr_in_dnat), priority=    0, match=(1),
            action=(next;)
          table= 5(  lr_in_arp_resolve), priority=    0, match=(1),
            action=(get_arp(outport, reg0); next;)
          table= 6(  lr_in_arp_request), priority=  100,
            match=(eth.dst == 00:00:00:00:00:00),
            action=(arp { eth.dst = ff:ff:ff:ff:ff:ff; arp.spa = reg1;
                    arp.op = 1; output; };)
          table= 6(  lr_in_arp_request), priority=    0, match=(1),
            action=(output;)
        Datapath: 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa  Pipeline: egress
          table= 0(        lr_out_snat), priority=    0, match=(1),
            action=(next;)

#. The OVN controller service on each compute node translates these objects
   into flows on the integration bridge ``br-int``.

   .. code-block:: console

      # ovs-ofctl dump-flows br-int
      cookie=0x0, duration=6.402s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x5,vlan_tci=0x1000/0x1000
          actions=drop
      cookie=0x0, duration=6.402s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x5,
          dl_src=01:00:00:00:00:00/01:00:00:00:00:00
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_dst=127.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_dst=0.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_dst=224.0.0.0/4
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,ip,metadata=0x5,nw_dst=224.0.0.0/4
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_src=255.255.255.255
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_src=127.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x5,nw_src=0.0.0.0/8
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,arp,metadata=0x5,arp_op=2
          actions=push:NXM_NX_REG0[],push:NXM_OF_ETH_SRC[],
              push:NXM_NX_ARP_SHA[],push:NXM_OF_ARP_SPA[],
              pop:NXM_NX_REG0[],pop:NXM_OF_ETH_SRC[],
              controller(userdata=00.00.00.01.00.00.00.00),
              pop:NXM_OF_ETH_SRC[],pop:NXM_NX_REG0[]
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,metadata=0x5,dl_dst=ff:ff:ff:ff:ff:ff
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=30,ip,metadata=0x5,nw_ttl=0
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=30,ip,metadata=0x5,nw_ttl=1
          actions=drop
      cookie=0x0, duration=6.402s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5
          actions=resubmit(,18)
      cookie=0x0, duration=6.402s, table=18, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5
          actions=resubmit(,19)
      cookie=0x0, duration=6.402s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5
          actions=resubmit(,20)
      cookie=0x0, duration=6.402s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5
          actions=resubmit(,32)
      cookie=0x0, duration=6.402s, table=48, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x5
          actions=resubmit(,49)

Attach a self-service network to the router
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Self-service networks, particularly subnets, must interface with a
router to enable connectivity with other self-service and provider
networks.

#. On the controller node, add the self-service network subnet
   ``selfservice-v4`` to the router ``router``.

   .. code-block:: console

      $ openstack router add subnet router selfservice-v4

   .. note::

      This command provides no output.

OVN operations
^^^^^^^^^^^^^^

The OVN mechanism driver and OVN perform the following operations when
adding a subnet as an interface on a router.

#. The OVN mechanism driver translates the operation into logical
   objects and devices in the OVN northbound database and performs a
   series of operations on them.

   * Create a logical port.

     .. code-block:: console

        _uuid               : 4c9e70b1-fff0-4d0d-af8e-42d3896eb76f
        addresses           : ["fa:16:3e:0c:55:62 192.168.1.1"]
        enabled             : true
        external_ids        : {"neutron:port_name"=""}
        name                : "5b72d278-5b16-44a6-9aa0-9e513a429506"
        options             : {router-port="lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"}
        parent_name         : []
        port_security       : []
        tag                 : []
        type                : router
        up                  : false

   * Add the logical port to logical switch.

     .. code-block:: console

        _uuid               : 0ab40684-7cf8-4d6c-ae8b-9d9143762d37
        acls                : []
        external_ids        : {"neutron:network_name"="selfservice"}
        name                : "neutron-d5aadceb-d8d6-41c8-9252-c5e0fe6c26a5"
        ports               : [1ed7c28b-dc69-42b8-bed6-46477bb8b539,
                               4c9e70b1-fff0-4d0d-af8e-42d3896eb76f,
                               ae10a5e0-db25-4108-b06a-d2d5c127d9c4]

   * Create a logical router port object.

     .. code-block:: console

        _uuid               : f60ccb93-7b3d-4713-922c-37104b7055dc
        enabled             : []
        external_ids        : {}
        mac                 : "fa:16:3e:0c:55:62"
        name                : "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"
        network             : "192.168.1.1/24"
        peer                : []

   * Add the logical router port to the logical router object.

     .. code-block:: console

        _uuid               : 1c2e340d-dac9-496b-9e86-1065f9dab752
        default_gw          : []
        enabled             : []
        external_ids        : {"neutron:router_name"="router"}
        name                : "neutron-a24fd760-1a99-4eec-9f02-24bb284ff708"
        ports               : [f60ccb93-7b3d-4713-922c-37104b7055dc]
        static_routes       : []

#. The OVN northbound service translates these objects into logical flows,
   datapath bindings, and the appropriate multicast groups in the OVN
   southbound database.

   * Logical flows in the logical router datapath

     .. code-block:: console

        Datapath: 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa  Pipeline: ingress
          table= 0(    lr_in_admission), priority=   50,
            match=((eth.mcast || eth.dst == fa:16:3e:0c:55:62) &&
                   inport == "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"),
            action=(next;)
          table= 1(     lr_in_ip_input), priority=  100,
            match=(ip4.src == {192.168.1.1, 192.168.1.255}), action=(drop;)
          table= 1(     lr_in_ip_input), priority=   90,
            match=(ip4.dst == 192.168.1.1 && icmp4.type == 8 &&
                   icmp4.code == 0),
            action=(ip4.dst = ip4.src; ip4.src = 192.168.1.1; ip.ttl = 255;
                    icmp4.type = 0;
                    inport = ""; /* Allow sending out inport. */ next; )
          table= 1(     lr_in_ip_input), priority=   90,
            match=(inport == "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506" &&
                   arp.tpa == 192.168.1.1 && arp.op == 1),
            action=(eth.dst = eth.src; eth.src = fa:16:3e:0c:55:62;
                    arp.op = 2; /* ARP reply */ arp.tha = arp.sha;
                    arp.sha = fa:16:3e:0c:55:62; arp.tpa = arp.spa;
                    arp.spa = 192.168.1.1;
                    outport = "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506";
                    inport = ""; /* Allow sending out inport. */ output;)
          table= 1(     lr_in_ip_input), priority=   60,
            match=(ip4.dst == 192.168.1.1), action=(drop;)
          table= 4(   lr_in_ip_routing), priority=   24,
            match=(ip4.dst == 192.168.1.0/255.255.255.0),
            action=(ip.ttl--; reg0 = ip4.dst; reg1 = 192.168.1.1;
                    eth.src = fa:16:3e:0c:55:62;
                    outport = "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506";
                    next;)
        Datapath: 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa  Pipeline: egress
          table= 1(    lr_out_delivery), priority=  100,
            match=(outport == "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506),
            action=(output;)

   * Logical flows in the logical switch datapath

     .. code-block:: console

        Datapath: 611d35e8-b1e1-442c-bc07-7c6192ad6216  Pipeline: ingress
          table= 0(  ls_in_port_sec_l2), priority=   50,
            match=(inport == "5b72d278-5b16-44a6-9aa0-9e513a429506"),
            action=(next;)
          table= 3(      ls_in_pre_acl), priority=  110,
            match=(ip && inport == "5b72d278-5b16-44a6-9aa0-9e513a429506"),
            action=(next;)
          table= 9(      ls_in_arp_rsp), priority=   50,
            match=(arp.tpa == 192.168.1.1 && arp.op == 1),
            action=(eth.dst = eth.src; eth.src = fa:16:3e:0c:55:62;
                    arp.op = 2; /* ARP reply */ arp.tha = arp.sha;
                    arp.sha = fa:16:3e:0c:55:62; arp.tpa = arp.spa;
                    arp.spa = 192.168.1.1; outport = inport;
                    inport = ""; /* Allow sending out inport. */ output;)
          table=10(      ls_in_l2_lkup), priority=   50,
            match=(eth.dst == fa:16:3e:fa:76:8f),
            action=(outport = "f112b99a-8ccc-4c52-8733-7593fa0966ea"; output;)
        Datapath: 611d35e8-b1e1-442c-bc07-7c6192ad6216  Pipeline: egress
          table= 1(     ls_out_pre_acl), priority=  110,
            match=(ip && outport == "f112b99a-8ccc-4c52-8733-7593fa0966ea"),
            action=(next;)
          table= 7( ls_out_port_sec_l2), priority=   50,
            match=(outport == "f112b99a-8ccc-4c52-8733-7593fa0966ea"),
            action=(output;)

   * Port bindings

     .. code-block:: console

        _uuid               : 0f86395b-a0d8-40fd-b22c-4c9e238a7880
        chassis             : []
        datapath            : 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa
        logical_port        : "lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"
        mac                 : []
        options             : {peer="5b72d278-5b16-44a6-9aa0-9e513a429506"}
        parent_port         : []
        tag                 : []
        tunnel_key          : 1
        type                : patch

        _uuid               : 8d95ab8c-c2ea-4231-9729-7ecbfc2cd676
        chassis             : []
        datapath            : 4aef86e4-e54a-4c83-bb27-d65c670d4b51
        logical_port        : "5b72d278-5b16-44a6-9aa0-9e513a429506"
        mac                 : ["fa:16:3e:0c:55:62 192.168.1.1"]
        options             : {peer="lrp-5b72d278-5b16-44a6-9aa0-9e513a429506"}
        parent_port         : []
        tag                 : []
        tunnel_key          : 3
        type                : patch

   * Multicast groups

     .. code-block:: console

        _uuid               : 4a6191aa-d8ac-4e93-8306-b0d8fbbe4e35
        datapath            : 4aef86e4-e54a-4c83-bb27-d65c670d4b51
        name                : _MC_flood
        ports               : [8d95ab8c-c2ea-4231-9729-7ecbfc2cd676,
                               be71fac3-9f04-41c9-9951-f3f7f1fa1ec5,
                               da5c1269-90b7-4df2-8d76-d4575754b02d]
        tunnel_key          : 65535

   In addition, if the self-service network contains ports with IP addresses
   (typically instances or DHCP servers), OVN creates a logical flow for
   each port, similar to the following example.

   .. code-block:: console

      Datapath: 4a7485c6-a1ef-46a5-b57c-5ddb6ac15aaa  Pipeline: ingress
        table= 5(  lr_in_arp_resolve), priority=  100,
          match=(outport == "lrp-f112b99a-8ccc-4c52-8733-7593fa0966ea" &&
                 reg0 == 192.168.1.11),
          action=(eth.dst = fa:16:3e:b6:91:70; next;)

#. On each compute node, the OVN controller service creates patch ports,
   similar to the following example.

   .. code-block:: console

      7(patch-f112b99a-): addr:4e:01:91:2a:73:66
          config:     0
          state:      0
          speed: 0 Mbps now, 0 Mbps max
      8(patch-lrp-f112b): addr:be:9d:7b:31:bb:87
          config:     0
          state:      0
          speed: 0 Mbps now, 0 Mbps max

#. On all compute nodes, the OVN controller service creates the
   following additional flows:

   .. code-block:: console

      cookie=0x0, duration=6.667s, table=0, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,in_port=8
          actions=load:0x9->OXM_OF_METADATA[],load:0x1->NXM_NX_REG6[],
              resubmit(,16)
      cookie=0x0, duration=6.667s, table=0, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,in_port=7
          actions=load:0x7->OXM_OF_METADATA[],load:0x4->NXM_NX_REG6[],
              resubmit(,16)
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg6=0x4,metadata=0x7
          actions=resubmit(,17)
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg6=0x1,metadata=0x9,
              dl_dst=fa:16:3e:fa:76:8f
          actions=resubmit(,17)
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg6=0x1,metadata=0x9,
              dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
          actions=resubmit(,17)
      cookie=0x0, duration=6.674s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x9,nw_src=192.168.1.1
          actions=drop
      cookie=0x0, duration=6.673s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x9,nw_src=192.168.1.255
          actions=drop
      cookie=0x0, duration=6.673s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,arp,reg6=0x1,metadata=0x9,
              arp_tpa=192.168.1.1,arp_op=1
          actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
              mod_dl_src:fa:16:3e:fa:76:8f,load:0x2->NXM_OF_ARP_OP[],
              move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
              load:0xfa163efa768f->NXM_NX_ARP_SHA[],
              move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
              load:0xc0a80101->NXM_OF_ARP_SPA[],load:0x1->NXM_NX_REG7[],
              load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=6.673s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,icmp,metadata=0x9,nw_dst=192.168.1.1,
              icmp_type=8,icmp_code=0
          actions=move:NXM_OF_IP_SRC[]->NXM_OF_IP_DST[],mod_nw_src:192.168.1.1,
              load:0xff->NXM_NX_IP_TTL[],load:0->NXM_OF_ICMP_TYPE[],
              load:0->NXM_NX_REG6[],load:0->NXM_OF_IN_PORT[],resubmit(,18)
      cookie=0x0, duration=6.674s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=60,ip,metadata=0x9,nw_dst=192.168.1.1
          actions=drop
      cookie=0x0, duration=6.674s, table=20, n_packets=0, n_bytes=0,
          idle_age=6, priority=24,ip,metadata=0x9,nw_dst=192.168.1.0/24
          actions=dec_ttl(),move:NXM_OF_IP_DST[]->NXM_NX_REG0[],
              load:0xc0a80101->NXM_NX_REG1[],mod_dl_src:fa:16:3e:fa:76:8f,
              load:0x1->NXM_NX_REG7[],resubmit(,21)
      cookie=0x0, duration=6.674s, table=21, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg0=0xc0a80103,reg7=0x1,metadata=0x9
          actions=mod_dl_dst:fa:16:3e:d5:00:02,resubmit(,22)
      cookie=0x0, duration=6.674s, table=21, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg0=0xc0a80102,reg7=0x1,metadata=0x9
          actions=mod_dl_dst:fa:16:3e:82:8b:0e,resubmit(,22)
      cookie=0x0, duration=6.673s, table=21, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg0=0xc0a8010b,reg7=0x1,metadata=0x9
          actions=mod_dl_dst:fa:16:3e:b6:91:70,resubmit(,22)
      cookie=0x0, duration=6.673s, table=25, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,arp,metadata=0x7,arp_tpa=192.168.1.1,
              arp_op=1
          actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
              mod_dl_src:fa:16:3e:fa:76:8f,load:0x2->NXM_OF_ARP_OP[],
              move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
              load:0xfa163efa768f->NXM_NX_ARP_SHA[],
              move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
              load:0xc0a80101->NXM_OF_ARP_SPA[],
              move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
              load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=6.674s, table=26, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,metadata=0x7,dl_dst=fa:16:3e:fa:76:8f
          actions=load:0x4->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=6.667s, table=33, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x4,metadata=0x7
          actions=resubmit(,34)
      cookie=0x0, duration=6.667s, table=33, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x1,metadata=0x9
          actions=resubmit(,34)
      cookie=0x0, duration=6.667s, table=34, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg6=0x4,reg7=0x4,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.667s, table=34, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg6=0x1,reg7=0x1,metadata=0x9
          actions=drop
      cookie=0x0, duration=6.674s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=110,ipv6,reg7=0x4,metadata=0x7
          actions=resubmit(,50)
      cookie=0x0, duration=6.673s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=110,ip,reg7=0x4,metadata=0x7
          actions=resubmit(,50)
      cookie=0x0, duration=6.673s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x1,metadata=0x9
          actions=resubmit(,64)
      cookie=0x0, duration=6.673s, table=55, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg7=0x4,metadata=0x7
          actions=resubmit(,64)
      cookie=0x0, duration=6.667s, table=64, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x4,metadata=0x7
          actions=output:7
      cookie=0x0, duration=6.667s, table=64, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x1,metadata=0x9
          actions=output:8

#. On compute nodes not containing a port on the network, the OVN controller
   also creates additional flows.

   .. code-block:: console

      cookie=0x0, duration=6.673s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x7,
              dl_src=01:00:00:00:00:00/01:00:00:00:00:00
          actions=drop
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x7,vlan_tci=0x1000/0x1000
          actions=drop
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg6=0x3,metadata=0x7,
              dl_src=fa:16:3e:b6:91:70
          actions=resubmit(,17)
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg6=0x2,metadata=0x7
          actions=resubmit(,17)
      cookie=0x0, duration=6.674s, table=16, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg6=0x1,metadata=0x7
          actions=resubmit(,17)
      cookie=0x0, duration=6.674s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,ip,reg6=0x3,metadata=0x7,
              dl_src=fa:16:3e:b6:91:70,nw_src=192.168.1.11
          actions=resubmit(,18)
      cookie=0x0, duration=6.674s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,udp,reg6=0x3,metadata=0x7,
              dl_src=fa:16:3e:b6:91:70,nw_src=0.0.0.0,
              nw_dst=255.255.255.255,tp_src=68,tp_dst=67
          actions=resubmit(,18)
      cookie=0x0, duration=6.674s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,ip,reg6=0x3,metadata=0x7,
              dl_src=fa:16:3e:b6:91:70
          actions=drop
      cookie=0x0, duration=6.673s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,ipv6,reg6=0x3,metadata=0x7,
              dl_src=fa:16:3e:b6:91:70
          actions=drop
      cookie=0x0, duration=6.670s, table=17, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,18)
      cookie=0x0, duration=6.674s, table=18, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,arp,reg6=0x3,metadata=0x7,
              dl_src=fa:16:3e:b6:91:70,arp_spa=192.168.1.11,
              arp_sha=fa:16:3e:b6:91:70
          actions=resubmit(,19)
      cookie=0x0, duration=6.673s, table=18, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,icmp6,reg6=0x3,metadata=0x7,icmp_type=135,
              icmp_code=0
          actions=drop
      cookie=0x0, duration=6.673s, table=18, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,icmp6,reg6=0x3,metadata=0x7,icmp_type=136,
              icmp_code=0
          actions=drop
      cookie=0x0, duration=6.673s, table=18, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,arp,reg6=0x3,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.673s, table=18, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,19)
      cookie=0x0, duration=6.673s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=110,icmp6,metadata=0x7,icmp_type=136,icmp_code=0
          actions=resubmit(,20)
      cookie=0x0, duration=6.673s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=110,icmp6,metadata=0x7,icmp_type=135,icmp_code=0
          actions=resubmit(,20)
      cookie=0x0, duration=6.674s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
      cookie=0x0, duration=6.670s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[0],resubmit(,20)
      cookie=0x0, duration=6.674s, table=19, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,20)
      cookie=0x0, duration=6.673s, table=20, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,21)
      cookie=0x0, duration=6.674s, table=21, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,reg0=0x1/0x1,metadata=0x7
          actions=ct(table=22,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=6.670s, table=21, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,reg0=0x1/0x1,metadata=0x7
          actions=ct(table=22,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=6.674s, table=21, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,22)
      cookie=0x0, duration=6.674s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,ct_state=-new+est-rel-inv+trk,metadata=0x7
          actions=resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,ct_state=-new-est+rel-inv+trk,metadata=0x7
          actions=resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,ct_state=+inv+trk,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,icmp6,metadata=0x7,icmp_type=135,
              icmp_code=0
          actions=resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,icmp6,metadata=0x7,icmp_type=136,
              icmp_code=0
          actions=resubmit(,23)
      cookie=0x0, duration=6.674s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,udp,reg6=0x3,metadata=0x7,
              nw_dst=255.255.255.255,tp_src=68,tp_dst=67
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
      cookie=0x0, duration=6.674s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,udp,reg6=0x3,metadata=0x7,
              nw_dst=192.168.1.0/24,tp_src=68,tp_dst=67
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,ct_state=+new+trk,ipv6,reg6=0x3,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,ct_state=+new+trk,ip,reg6=0x3,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
      cookie=0x0, duration=6.674s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=2001,ip,reg6=0x3,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=2001,ipv6,reg6=0x3,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.674s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=1,ipv6,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=1,ip,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,23)
      cookie=0x0, duration=6.673s, table=22, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,23)
      cookie=0x0, duration=6.673s, table=23, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,24)
      cookie=0x0, duration=6.674s, table=24, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,reg0=0x2/0x2,metadata=0x7
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,25)
      cookie=0x0, duration=6.674s, table=24, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,reg0=0x2/0x2,metadata=0x7
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,25)
      cookie=0x0, duration=6.673s, table=24, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,reg0=0x4/0x4,metadata=0x7
          actions=ct(table=25,zone=NXM_NX_REG5[0..15],nat)
      cookie=0x0, duration=6.670s, table=24, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,reg0=0x4/0x4,metadata=0x7
          actions=ct(table=25,zone=NXM_NX_REG5[0..15],nat)
      cookie=0x0, duration=6.674s, table=24, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,25)
      cookie=0x0, duration=6.673s, table=25, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,arp,metadata=0x7,arp_tpa=192.168.1.11,
              arp_op=1
          actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
              mod_dl_src:fa:16:3e:b6:91:70,load:0x2->NXM_OF_ARP_OP[],
              move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
              load:0xfa163eb69170->NXM_NX_ARP_SHA[],
              move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
              load:0xc0a8010b->NXM_OF_ARP_SPA[],
              move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
              load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=6.670s, table=25, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,arp,metadata=0x7,arp_tpa=192.168.1.3,arp_op=1
          actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
              mod_dl_src:fa:16:3e:d5:00:02,load:0x2->NXM_OF_ARP_OP[],
              move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
              load:0xfa163ed50002->NXM_NX_ARP_SHA[],
              move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
              load:0xc0a80103->NXM_OF_ARP_SPA[],
              move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
              load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=6.670s, table=25, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,arp,metadata=0x7,arp_tpa=192.168.1.2,
              arp_op=1
          actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],
              mod_dl_src:fa:16:3e:82:8b:0e,load:0x2->NXM_OF_ARP_OP[],
              move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],
              load:0xfa163e828b0e->NXM_NX_ARP_SHA[],
              move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],
              load:0xc0a80102->NXM_OF_ARP_SPA[],
              move:NXM_NX_REG6[]->NXM_NX_REG7[],load:0->NXM_NX_REG6[],
              load:0->NXM_OF_IN_PORT[],resubmit(,32)
      cookie=0x0, duration=6.674s, table=25, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,26)
      cookie=0x0, duration=6.674s, table=26, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x7,
              dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
          actions=load:0xffff->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=6.674s, table=26, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,metadata=0x7,dl_dst=fa:16:3e:d5:00:02
          actions=load:0x2->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=6.673s, table=26, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,metadata=0x7,dl_dst=fa:16:3e:b6:91:70
          actions=load:0x3->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=6.670s, table=26, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,metadata=0x7,dl_dst=fa:16:3e:82:8b:0e
          actions=load:0x1->NXM_NX_REG7[],resubmit(,32)
      cookie=0x0, duration=6.674s, table=32, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x3,metadata=0x7
          actions=load:0x7->NXM_NX_TUN_ID[0..23],
              set_field:0x3/0xffffffff->tun_metadata0,
              move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:3
      cookie=0x0, duration=6.673s, table=32, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x2,metadata=0x7
          actions=load:0x7->NXM_NX_TUN_ID[0..23],
              set_field:0x2/0xffffffff->tun_metadata0,
              move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:3
      cookie=0x0, duration=6.670s, table=32, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,reg7=0x1,metadata=0x7
          actions=load:0x7->NXM_NX_TUN_ID[0..23],
              set_field:0x1/0xffffffff->tun_metadata0,
              move:NXM_NX_REG6[0..14]->NXM_NX_TUN_METADATA0[16..30],output:5
      cookie=0x0, duration=6.674s, table=48, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,49)
      cookie=0x0, duration=6.674s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=110,icmp6,metadata=0x7,icmp_type=135,icmp_code=0
          actions=resubmit(,50)
      cookie=0x0, duration=6.673s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=110,icmp6,metadata=0x7,icmp_type=136,icmp_code=0
          actions=resubmit(,50)
      cookie=0x0, duration=6.674s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
      cookie=0x0, duration=6.673s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[0],resubmit(,50)
      cookie=0x0, duration=6.674s, table=49, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,50)
      cookie=0x0, duration=6.674s, table=50, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,reg0=0x1/0x1,metadata=0x7
          actions=ct(table=51,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=6.673s, table=50, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,reg0=0x1/0x1,metadata=0x7
          actions=ct(table=51,zone=NXM_NX_REG5[0..15])
      cookie=0x0, duration=6.673s, table=50, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,51)
      cookie=0x0, duration=6.670s, table=51, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,52)
      cookie=0x0, duration=6.674s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,ct_state=+inv+trk,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.674s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,ct_state=-new+est-rel-inv+trk,metadata=0x7
          actions=resubmit(,53)
      cookie=0x0, duration=6.673s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,ct_state=-new-est+rel-inv+trk,metadata=0x7
          actions=resubmit(,53)
      cookie=0x0, duration=6.673s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,icmp6,metadata=0x7,icmp_type=136,
              icmp_code=0
          actions=resubmit(,53)
      cookie=0x0, duration=6.673s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=65535,icmp6,metadata=0x7,icmp_type=135,
              icmp_code=0
          actions=resubmit(,53)
      cookie=0x0, duration=6.674s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,ct_state=+new+trk,ip,reg7=0x3,metadata=0x7,
              nw_src=192.168.1.11
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
      cookie=0x0, duration=6.670s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,ct_state=+new+trk,ip,reg7=0x3,metadata=0x7,
              nw_src=192.168.1.11
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
      cookie=0x0, duration=6.670s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,udp,reg7=0x3,metadata=0x7,
              nw_src=192.168.1.0/24,tp_src=67,tp_dst=68
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
      cookie=0x0, duration=6.670s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=2002,ct_state=+new+trk,ipv6,reg7=0x3,
              metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
      cookie=0x0, duration=6.673s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=2001,ip,reg7=0x3,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.673s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=2001,ipv6,reg7=0x3,metadata=0x7
          actions=drop
      cookie=0x0, duration=6.674s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=1,ip,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
      cookie=0x0, duration=6.674s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=1,ipv6,metadata=0x7
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)
      cookie=0x0, duration=6.674s, table=52, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,53)
      cookie=0x0, duration=6.674s, table=53, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,reg0=0x4/0x4,metadata=0x7
          actions=ct(table=54,zone=NXM_NX_REG5[0..15],nat)
      cookie=0x0, duration=6.674s, table=53, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,reg0=0x4/0x4,metadata=0x7
          actions=ct(table=54,zone=NXM_NX_REG5[0..15],nat)
      cookie=0x0, duration=6.673s, table=53, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ipv6,reg0=0x2/0x2,metadata=0x7
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,54)
      cookie=0x0, duration=6.673s, table=53, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,ip,reg0=0x2/0x2,metadata=0x7
          actions=ct(commit,zone=NXM_NX_REG5[0..15]),resubmit(,54)
      cookie=0x0, duration=6.674s, table=53, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,54)
      cookie=0x0, duration=6.674s, table=54, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,ip,reg7=0x3,metadata=0x7,
              dl_dst=fa:16:3e:b6:91:70,nw_dst=255.255.255.255
          actions=resubmit(,55)
      cookie=0x0, duration=6.673s, table=54, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,ip,reg7=0x3,metadata=0x7,
              dl_dst=fa:16:3e:b6:91:70,nw_dst=192.168.1.11
          actions=resubmit(,55)
      cookie=0x0, duration=6.673s, table=54, n_packets=0, n_bytes=0,
          idle_age=6, priority=90,ip,reg7=0x3,metadata=0x7,
              dl_dst=fa:16:3e:b6:91:70,nw_dst=224.0.0.0/4
          actions=resubmit(,55)
      cookie=0x0, duration=6.670s, table=54, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,ip,reg7=0x3,metadata=0x7,
              dl_dst=fa:16:3e:b6:91:70
          actions=drop
      cookie=0x0, duration=6.670s, table=54, n_packets=0, n_bytes=0,
          idle_age=6, priority=80,ipv6,reg7=0x3,metadata=0x7,
              dl_dst=fa:16:3e:b6:91:70
          actions=drop
      cookie=0x0, duration=6.674s, table=54, n_packets=0, n_bytes=0,
          idle_age=6, priority=0,metadata=0x7
          actions=resubmit(,55)
      cookie=0x0, duration=6.673s, table=55, n_packets=0, n_bytes=0,
          idle_age=6, priority=100,metadata=0x7,
              dl_dst=01:00:00:00:00:00/01:00:00:00:00:00
          actions=resubmit(,64)
      cookie=0x0, duration=6.674s, table=55, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg7=0x3,metadata=0x7,
              dl_dst=fa:16:3e:b6:91:70
          actions=resubmit(,64)
      cookie=0x0, duration=6.673s, table=55, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg7=0x1,metadata=0x7
          actions=resubmit(,64)
      cookie=0x0, duration=6.670s, table=55, n_packets=0, n_bytes=0,
          idle_age=6, priority=50,reg7=0x2,metadata=0x7
          actions=resubmit(,64)

#. On compute nodes containing a port on the network, the OVN controller
   also creates an additional flow.

   .. code-block:: console

      cookie=0x0, duration=13.358s, table=52, n_packets=0, n_bytes=0,
          idle_age=13, priority=2002,ct_state=+new+trk,ipv6,reg7=0x3,
              metadata=0x7,ipv6_src=::
          actions=load:0x1->NXM_NX_REG0[1],resubmit(,53)

.. todo: Future commit

   Attach the router to a second self-service network
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. todo: Add after NAT patches merge.

   Attach the router to an external network
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
