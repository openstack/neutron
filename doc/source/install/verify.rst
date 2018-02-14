Verify operation
~~~~~~~~~~~~~~~~

.. note::

   Perform these commands on the controller node.

#. Source the ``admin`` credentials to gain access to admin-only CLI
   commands:

   .. code-block:: console

      $ . admin-openrc

   .. end

#. List loaded extensions to verify successful launch of the
   ``neutron-server`` process:

   .. code-block:: console

      $ openstack extension list --network

      +---------------------------+---------------------------+----------------------------+
      | Name                      | Alias                     | Description                |
      +---------------------------+---------------------------+----------------------------+
      | Default Subnetpools       | default-subnetpools       | Provides ability to mark   |
      |                           |                           | and use a subnetpool as    |
      |                           |                           | the default                |
      | Availability Zone         | availability_zone         | The availability zone      |
      |                           |                           | extension.                 |
      | Network Availability Zone | network_availability_zone | Availability zone support  |
      |                           |                           | for network.               |
      | Port Binding              | binding                   | Expose port bindings of a  |
      |                           |                           | virtual port to external   |
      |                           |                           | application                |
      | agent                     | agent                     | The agent management       |
      |                           |                           | extension.                 |
      | Subnet Allocation         | subnet_allocation         | Enables allocation of      |
      |                           |                           | subnets from a subnet pool |
      | DHCP Agent Scheduler      | dhcp_agent_scheduler      | Schedule networks among    |
      |                           |                           | dhcp agents                |
      | Tag support               | tag                       | Enables to set tag on      |
      |                           |                           | resources.                 |
      | Neutron external network  | external-net              | Adds external network      |
      |                           |                           | attribute to network       |
      |                           |                           | resource.                  |
      | Neutron Service Flavors   | flavors                   | Flavor specification for   |
      |                           |                           | Neutron advanced services  |
      | Network MTU               | net-mtu                   | Provides MTU attribute for |
      |                           |                           | a network resource.        |
      | Network IP Availability   | network-ip-availability   | Provides IP availability   |
      |                           |                           | data for each network and  |
      |                           |                           | subnet.                    |
      | Quota management support  | quotas                    | Expose functions for       |
      |                           |                           | quotas management per      |
      |                           |                           | tenant                     |
      | Provider Network          | provider                  | Expose mapping of virtual  |
      |                           |                           | networks to physical       |
      |                           |                           | networks                   |
      | Multi Provider Network    | multi-provider            | Expose mapping of virtual  |
      |                           |                           | networks to multiple       |
      |                           |                           | physical networks          |
      | Address scope             | address-scope             | Address scopes extension.  |
      | Subnet service types      | subnet-service-types      | Provides ability to set    |
      |                           |                           | the subnet service_types   |
      |                           |                           | field                      |
      | Resource timestamps       | standard-attr-timestamp   | Adds created_at and        |
      |                           |                           | updated_at fields to all   |
      |                           |                           | Neutron resources that     |
      |                           |                           | have Neutron standard      |
      |                           |                           | attributes.                |
      | Neutron Service Type      | service-type              | API for retrieving service |
      | Management                |                           | providers for Neutron      |
      |                           |                           | advanced services          |
      | Tag support for           | tag-ext                   | Extends tag support to     |
      | resources: subnet,        |                           | more L2 and L3 resources.  |
      | subnetpool, port, router  |                           |                            |
      | Neutron Extra DHCP opts   | extra_dhcp_opt            | Extra options              |
      |                           |                           | configuration for DHCP.    |
      |                           |                           | For example PXE boot       |
      |                           |                           | options to DHCP clients    |
      |                           |                           | can be specified (e.g.     |
      |                           |                           | tftp-server, server-ip-    |
      |                           |                           | address, bootfile-name)    |
      | Resource revision numbers | standard-attr-revisions   | This extension will        |
      |                           |                           | display the revision       |
      |                           |                           | number of neutron          |
      |                           |                           | resources.                 |
      | Pagination support        | pagination                | Extension that indicates   |
      |                           |                           | that pagination is         |
      |                           |                           | enabled.                   |
      | Sorting support           | sorting                   | Extension that indicates   |
      |                           |                           | that sorting is enabled.   |
      | security-group            | security-group            | The security groups        |
      |                           |                           | extension.                 |
      | RBAC Policies             | rbac-policies             | Allows creation and        |
      |                           |                           | modification of policies   |
      |                           |                           | that control tenant access |
      |                           |                           | to resources.              |
      | standard-attr-description | standard-attr-description | Extension to add           |
      |                           |                           | descriptions to standard   |
      |                           |                           | attributes                 |
      | Port Security             | port-security             | Provides port security     |
      | Allowed Address Pairs     | allowed-address-pairs     | Provides allowed address   |
      |                           |                           | pairs                      |
      | project_id field enabled  | project-id                | Extension that indicates   |
      |                           |                           | that project_id field is   |
      |                           |                           | enabled.                   |
      +---------------------------+---------------------------+----------------------------+

   .. end

   .. note::

      Actual output may differ slightly from this example.


You can perform further testing of your networking using the
`neutron-sanity-check command line client <https://docs.openstack.org/cli-reference/neutron-sanity-check.html>`_.

Use the verification section for the networking option that you chose to
deploy.

.. toctree::

   verify-option1.rst
   verify-option2.rst
