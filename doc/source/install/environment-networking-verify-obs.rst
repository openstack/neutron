Verify connectivity
-------------------

We recommend that you verify network connectivity to the Internet and
among the nodes before proceeding further.

#. From the *controller* node, test access to the Internet:

   .. code-block:: console

      # ping -c 4 openstack.org

      PING openstack.org (174.143.194.225) 56(84) bytes of data.
      64 bytes from 174.143.194.225: icmp_seq=1 ttl=54 time=18.3 ms
      64 bytes from 174.143.194.225: icmp_seq=2 ttl=54 time=17.5 ms
      64 bytes from 174.143.194.225: icmp_seq=3 ttl=54 time=17.5 ms
      64 bytes from 174.143.194.225: icmp_seq=4 ttl=54 time=17.4 ms

      --- openstack.org ping statistics ---
      4 packets transmitted, 4 received, 0% packet loss, time 3022ms
      rtt min/avg/max/mdev = 17.489/17.715/18.346/0.364 ms

   .. end

#. From the *controller* node, test access to the management interface on the
   *compute* node:

   .. code-block:: console

      # ping -c 4 compute1

      PING compute1 (10.0.0.31) 56(84) bytes of data.
      64 bytes from compute1 (10.0.0.31): icmp_seq=1 ttl=64 time=0.263 ms
      64 bytes from compute1 (10.0.0.31): icmp_seq=2 ttl=64 time=0.202 ms
      64 bytes from compute1 (10.0.0.31): icmp_seq=3 ttl=64 time=0.203 ms
      64 bytes from compute1 (10.0.0.31): icmp_seq=4 ttl=64 time=0.202 ms

      --- compute1 ping statistics ---
      4 packets transmitted, 4 received, 0% packet loss, time 3000ms
      rtt min/avg/max/mdev = 0.202/0.217/0.263/0.030 ms

   .. end

#. From the *compute* node, test access to the Internet:

   .. code-block:: console

      # ping -c 4 openstack.org

      PING openstack.org (174.143.194.225) 56(84) bytes of data.
      64 bytes from 174.143.194.225: icmp_seq=1 ttl=54 time=18.3 ms
      64 bytes from 174.143.194.225: icmp_seq=2 ttl=54 time=17.5 ms
      64 bytes from 174.143.194.225: icmp_seq=3 ttl=54 time=17.5 ms
      64 bytes from 174.143.194.225: icmp_seq=4 ttl=54 time=17.4 ms

      --- openstack.org ping statistics ---
      4 packets transmitted, 4 received, 0% packet loss, time 3022ms
      rtt min/avg/max/mdev = 17.489/17.715/18.346/0.364 ms

   .. end

#. From the *compute* node, test access to the management interface on the
   *controller* node:

   .. code-block:: console

      # ping -c 4 controller

      PING controller (10.0.0.11) 56(84) bytes of data.
      64 bytes from controller (10.0.0.11): icmp_seq=1 ttl=64 time=0.263 ms
      64 bytes from controller (10.0.0.11): icmp_seq=2 ttl=64 time=0.202 ms
      64 bytes from controller (10.0.0.11): icmp_seq=3 ttl=64 time=0.203 ms
      64 bytes from controller (10.0.0.11): icmp_seq=4 ttl=64 time=0.202 ms

      --- controller ping statistics ---
      4 packets transmitted, 4 received, 0% packet loss, time 3000ms
      rtt min/avg/max/mdev = 0.202/0.217/0.263/0.030 ms

   .. end

.. note::

   Your distribution enables a restrictive firewall by
   default. During the installation process, certain steps will fail
   unless you alter or disable the firewall. For more information
   about securing your environment, refer to the `OpenStack Security
   Guide <https://docs.openstack.org/security-guide/>`_.


