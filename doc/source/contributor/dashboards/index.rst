CI Status Dashboards
====================

Gerrit Dashboards
-----------------

- `Neutron priority reviews <https://review.opendev.org/dashboard/?title=Neutron+Priorities+Dashboard&foreach=(project:openstack/neutron+OR+project:openstack/neutron-lib+OR+project:openstack/neutron-tempest-plugin+OR+project:openstack/python-neutronclient+OR+project:openstack/neutron-specs+OR+project:openstack/networking-bagpipe+OR+project:openstack/networking-bgpvpn+OR+OR+project:openstack/networking-ovn+OR+project:openstack/networking-sfc+OR+project:openstack/neutron-dynamic-routing+OR+project:openstack/neutron-fwaas+OR+project:openstack/neutron-fwaas-dashboard+OR+project:openstack/neutron-vpnaas+OR+project:openstack/neutron-vpnaas-dashboard+OR+project:openstack/os-ken+OR+project:openstack/ovsdbapp)+status:open&High+Priority+Changes=label:Review-Priority=2&Priority+Changes=label:Review-Priority=1&Blocked+Reviews=label:Review-Priority=-1>`_
- `Neutron master branch reviews <https://review.opendev.org/dashboard/?title=Neutron+Review+Inbox+(master+branch+only)&foreach=(project:openstack/neutron+OR+project:openstack/neutron-lib+OR+project:openstack/neutron-tempest-plugin+OR+project:openstack/python-neutronclient+OR+project:openstack/neutron-specs)+status:open+NOT+owner:self+NOT+label:Workflow%3C=-1+label:Verified%3E=1,zuul+NOT+reviewedby:self+branch:master&Needs+Feedback+(Changes+older+than+5+days+that+have+not+been+reviewed+by+anyone)=NOT+label:Code-Review%3C=-1+NOT+label:Code-Review%3E=1+age:5d&You+are+a+reviewer,+but+haven't+voted+in+the+current+revision=NOT+label:Code-Review%3C=-1,self+NOT+label:Code-Review%3E=1,self+reviewer:self&Needs+final+%2B2=label:Code-Review%3E=2+NOT+(reviewerin:neutron-core+label:Code-Review%3C=-1)+limit:50&Passed+Zuul,+No+Negative+Core+Feedback=NOT+label:Code-Review%3E=2+NOT+(reviewerin:neutron-core+label:Code-Review%3C=-1)+limit:50&Wayward+Changes+(Changes+with+no+code+review+in+the+last+2days)=NOT+label:Code-Review%3C=-1+NOT+label:Code-Review%3E=1+age:2d>`_
- `Neutron subproject reviews (master branch) <https://review.opendev.org/dashboard/?title=Neutron+Sub+Projects+Review+Inbox&foreach=(project:openstack/networking-bagpipe+OR+project:openstack/networking-bgpvpn+OR+project:openstack/networking-ovn+OR+project:openstack/networking-sfc+OR+project:openstack/neutron-dynamic-routing+OR+project:openstack/neutron-fwaas+OR+project:openstack/neutron-vpnaas+OR+project:openstack/ovsdbapp)+status:open+NOT+owner:self+NOT+label:Workflow%3C=-1+label:Verified%3E=1,zuul+NOT+reviewedby:self+branch:master&Needs+Feedback+(Changes+older+than+5+days+that+have+not+been+reviewed+by+anyone)=NOT+label:Code-Review%3C=-1+NOT+label:Code-Review%3E=1+age:5d&You+are+a+reviewer,+but+haven't+voted+in+the+current+revision=NOT+label:Code-Review%3C=-1,self+NOT+label:Code-Review%3E=1,self+reviewer:self&Needs+final+%2B2=label:Code-Review%3E=2+NOT(reviewerin:neutron-core+label:Code-Review%3C=-1)+limit:50&Passed+Zuul,+No+Negative+Core+Feedback=NOT+label:Code-Review%3E=2+NOT(reviewerin:neutron-core+label:Code-Review%3C=-1)+limit:50&Wayward+Changes+(Changes+with+no+code+review+in+the+last+2days)=NOT+label:Code-Review%3C=-1+NOT+label:Code-Review%3E=1+age:2d>`_
- `Neutron stable branch reviews <https://review.opendev.org/dashboard/?title=Neutron+Stable+Related+Projects+Review+Inbox&foreach=(+project:openstack/networking-bagpipe+OR+project:openstack/networking-bgpvpn+OR+project:openstack/networking-odl+OR+project:openstack/networking-ovn+OR+project:openstack/networking-sfc+OR+project:openstack/neutron+OR+project:openstack/neutron-dynamic-routing+OR+project:openstack/neutron-fwaas+OR+project:openstack/neutron-vpnaas+OR+project:openstack/neutron-lib+OR+project:openstack/ovsdbapp+OR+project:openstack/python-neutronclient)+status:open+NOT+owner:self+NOT+label:Workflow%3C=-1+label:Verified%3E=1,zuul+NOT+reviewedby:self+branch:^stable/.*&Needs+Feedback+(Changes+older+than+5+days+that+have+not+been+reviewed+by+anyone)=NOT+label:Code-Review%3C=-1+NOT+label:Code-Review%3E=1+age:5d&You+are+a+reviewer,+but+haven't+voted+in+the+current+revision=NOT+label:Code-Review%3C=-1,self+NOT+label:Code-Review%3E=1,self+reviewer:self&Needs+final+%2B2=label:Code-Review%3E=2+NOT(reviewerin:neutron-stable-maint+label:Code-Review%3C=-1)+limit:50&Passed+Zuul,+No+Negative+Core+Feedback=NOT+label:Code-Review%3E=2+NOT(reviewerin:neutron-stable-maint+label:Code-Review%3C=-1)+limit:50&Wayward+Changes+(Changes+with+no+code+review+in+the+last+2days)=NOT+label:Code-Review%3C=-1+NOT+label:Code-Review%3E=1+age:2d>`_
- `Neutron Infra reviews <https://review.opendev.org/dashboard/?title=Neutron+Infra+Review+Inbox&foreach=(project:openstack-infra/project-config+OR+project:openstack-infra/openstack-zuul-jobs+OR+project:openstack-infra/devstack-gate)+status:open+NOT+owner:self+NOT+label:Workflow%3C=-1+label:Verified%3E=1,zuul+NOT+reviewedby:self&Neutron+related+infra+reviews=(message:"neutron"+OR+message:"networking-"+OR+message:"n8g-"+OR+message:"ovsdbapp"+OR+(comment:"neutron"+(comment:"liaison"+OR+comment:"liason")))>`_

These dashboard links can be generated by `Gerrit Dashboard Creator`_.
Useful dashboard definitions are found in ``dashboards`` directory.

.. _Gerrit Dashboard Creator: https://github.com/openstack/gerrit-dash-creator

Grafana Dashboards
------------------

Look for neutron and networking-* dashboard by names by going to the following
link:

`Grafana <https://grafana.opendev.org/>`_

For instance:

* `Neutron <https://grafana.opendev.org/d/f913631585/neutron-failure-rate>`_
* `Neutron-lib <https://grafana.opendev.org/d/92ab2dc01e/neutron-lib-failure-rate>`_
