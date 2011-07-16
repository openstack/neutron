

import os


def get_view_builder(req):
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for Portprofile, 
    derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, portprofile_data, is_detail=False):
        """Generic method used to generate a portprofile entity."""
        print "portprofile-DATA:%s" %portprofile_data
        if is_detail:
            portprofile = self._build_detail(portprofile_data)
        else:
            portprofile = self._build_simple(portprofile_data)
        return portprofile
    
    def _build_simple(self, portprofile_data):
        """Return a simple model of a server."""
        return dict(portprofile=dict(id=portprofile_data['profile-id']))
    
    def _build_detail(self, portprofile_data):
        """Return a simple model of a server."""
        if (portprofile_data['assignment']==None):
            return dict(portprofile=dict(id=portprofile_data['profile-id'],
                                name=portprofile_data['profile-name'],
                                vlan_id=portprofile_data['vlan-id']))
        else:
            return dict(portprofile=dict(id=portprofile_data['profile-id'],
                                name=portprofile_data['profile-name'],
                                vlan_id=portprofile_data['vlan-id'],
                                assignment=portprofile_data['assignment']))
