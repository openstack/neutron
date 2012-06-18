# TODO(bgh): DIST_DIR and target for plugin
PHONY: help

AGENT_DIST_DIR=ovs_quantum_agent
AGENT_DIST_TARBALL=ovs_quantum_agent.tgz
VERSION=$(shell python -c "import sys ; sys.path.append('../../../quantum/') ; import version ; print version.canonical_version_string()")
XAPI_PLUGINS_DIR=$(AGENT_DIST_DIR)/build/ovs-quantum-agent-$(VERSION)/etc/xapi.d/plugins
RPM_BUILD_ROOT=$(AGENT_DIST_DIR)/build/rpm

help:
	@echo "make agent-dist-xen - to create the ovs-quantum-agent-${VERSION}-1.noarch.rpm"
	@echo "make agent-dist-xen-python26 - to create ovs-quantum-agent-${VERSION}-1.noarch.rpm and use python2.6"

agent-dist-xen:QUANTUM_LIBS=$(AGENT_DIST_DIR)/build/ovs-quantum-agent-$(VERSION)/usr/lib/python2.4/site-packages
agent-dist-xen-python26:QUANTUM_LIBS=$(AGENT_DIST_DIR)/build/ovs-quantum-agent-$(VERSION)/usr/lib/python2.6/site-packages

agent-dist-xen agent-dist-xen-python26: distclean
	yum --enablerepo=base install rpm-build
	mkdir -p $(XAPI_PLUGINS_DIR)
	mkdir -p $(QUANTUM_LIBS)/{quantum/plugins/openvswitch/common,quantum/openstack/common}
	mkdir -p $(QUANTUM_LIBS)/quantum/agent/linux
	mkdir -p $(RPM_BUILD_ROOT)/BUILD $(RPM_BUILD_ROOT)/SOURCES
	mkdir -p $(RPM_BUILD_ROOT)/SRPMS $(RPM_BUILD_ROOT)/RPMS $(RPM_BUILD_ROOT)/SPECS
	cp agent/*.py $(XAPI_PLUGINS_DIR)
	cp agent/*.sh $(AGENT_DIST_DIR)
	cp agent/ovs-quantum-agent-xs_xcp.spec $(AGENT_DIST_DIR)
	sed -i "s/VERSION/$(VERSION)/" $(AGENT_DIST_DIR)/ovs-quantum-agent-xs_xcp.spec
	cp README $(AGENT_DIST_DIR)
	cp ../../../etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini $(XAPI_PLUGINS_DIR)
	cp ../../agent/linux/{ovs_lib.py,utils.py,__init__.py} $(QUANTUM_LIBS)/quantum/agent/linux
	test -d $(AGENT_DIST_DIR)/build/ovs-quantum-agent-$(VERSION)/usr/lib/python2.6/site-packages && \
		sed -i 's/Requires:.*/Requires:	   python26 python26-sqlalchemy python26-mysqldb/' \
			 $(AGENT_DIST_DIR)/ovs-quantum-agent-xs_xcp.spec || true
	test -d $(AGENT_DIST_DIR)/build/ovs-quantum-agent-$(VERSION)/usr/lib/python2.6/site-packages && \
		sed -i 's/env python/env python2.6/' $(XAPI_PLUGINS_DIR)/ovs_quantum_agent.py || true
	cp ../../__init__.py $(QUANTUM_LIBS)/quantum/
	cp ../../agent/__init__.py $(QUANTUM_LIBS)/quantum/agent/
	cp ../__init__.py $(QUANTUM_LIBS)/quantum/plugins/
	cp __init__.py $(QUANTUM_LIBS)/quantum/plugins/openvswitch/
	cp common/{config.py,__init__.py} $(QUANTUM_LIBS)/quantum/plugins/openvswitch/common/
	cp ../../openstack/__init__.py $(QUANTUM_LIBS)/quantum/openstack/
	cp ../../openstack/common/{cfg.py,iniparser.py,__init__.py} $(QUANTUM_LIBS)/quantum/openstack/common/
	tar -czvpf ${RPM_BUILD_ROOT}/SOURCES/ovs-quantum-agent-${VERSION}.tgz -C $(AGENT_DIST_DIR)/build ovs-quantum-agent-${VERSION}
	rpmbuild -ba --define "_topdir $(shell pwd)/$(RPM_BUILD_ROOT)" --clean $(AGENT_DIST_DIR)/ovs-quantum-agent-xs_xcp.spec
	@echo "Agent package created: ovs_quantum_agent/build/rpm/RPMS/noarch/ovs-quantum-agent-${VERSION}-1.noarch.rpm"
	@echo "See README for installation details"

all:

clean:
	$(find . -name *.pyc | xargs rm)

distclean:
	-rm -rf $(AGENT_DIST_DIR)
	-rm -f $(AGENT_DIST_TARBALL)
