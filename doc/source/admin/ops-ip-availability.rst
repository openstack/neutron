.. _ops-ip-availability:

=======================
IP availability metrics
=======================

Network IP Availability is an information-only API extension that allows
a user or process to determine the number of IP addresses that are consumed
across networks and the allocation pools of their subnets. This extension was
added to neutron in the Mitaka release.

This section illustrates how you can get the Network IP address availability
through the command-line interface.

Get Network IP address availability for all IPv4 networks:

.. code-block:: console

   $ openstack ip availability list

   +--------------------------------------+--------------+-----------+----------+
   | Network ID                           | Network Name | Total IPs | Used IPs |
   +--------------------------------------+--------------+-----------+----------+
   | 363a611a-b08b-4281-b64e-198d90cb94fd | private      |       253 |        3 |
   | c92d0605-caf2-4349-b1b8-8d5f9ac91df8 | public       |       253 |        1 |
   +--------------------------------------+--------------+-----------+----------+

Get Network IP address availability for all IPv6 networks:

.. code-block:: console

   $ openstack ip availability list --ip-version 6

   +--------------------------------------+--------------+----------------------+----------+
   | Network ID                           | Network Name | Total IPs            | Used IPs |
   +--------------------------------------+--------------+----------------------+----------+
   | 363a611a-b08b-4281-b64e-198d90cb94fd | private      | 18446744073709551614 |        3 |
   | c92d0605-caf2-4349-b1b8-8d5f9ac91df8 | public       | 18446744073709551614 |        1 |
   +--------------------------------------+--------------+----------------------+----------+

Get Network IP address availability statistics for a specific network:

.. code-block:: console

   $ openstack ip availability show NETWORKUUID

   +------------------------+--------------------------------------------------------------+
   | Field                  | Value                                                        |
   +------------------------+--------------------------------------------------------------+
   | network_id             | 0bf90de6-fc0f-4dba-b80d-96670dfb331a                         |
   | network_name           | public                                                       |
   | project_id             | 5669caad86a04256994cdf755df4d3c1                             |
   | subnet_ip_availability | cidr='192.0.2.224/28', ip_version='4', subnet_id='346806ee-  |
   |                        | a53e-44fd-968a-ddb2bcd2ba96', subnet_name='public_subnet',   |
   |                        | total_ips='13', used_ips='5'                                 |
   | total_ips              | 13                                                           |
   | used_ips               | 5                                                            |
   +------------------------+--------------------------------------------------------------+
