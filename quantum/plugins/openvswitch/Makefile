QUANTUM_PATH=../../../

# TODO(bgh): DIST_DIR and target for plugin

AGENT_DIST_DIR=ovs_quantum_agent
AGENT_DIST_TARBALL=ovs_quantum_agent.tgz

agent-dist: distclean
	mkdir $(AGENT_DIST_DIR)
	cp agent/*.py $(AGENT_DIST_DIR)
	cp agent/*.sh $(AGENT_DIST_DIR)
	cp README $(AGENT_DIST_DIR)
	cp ../../../etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini $(AGENT_DIST_DIR)
	tar -zcvf $(AGENT_DIST_TARBALL) $(AGENT_DIST_DIR)/
	@echo "Agent tarball created: $(AGENT_DIST_TARBALL)"
	@echo "See README for installation details"

all:

clean:
	$(find . -name *.pyc | xargs rm)

distclean:
	-rm -rf $(AGENT_DIST_DIR)
	-rm -f $(AGENT_DIST_TARBALL)

PHONY: agent-dist clean distclean
