

import os


def get_view_builder(req):
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for novatenant, 
    derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url
    
    def build_host(self, host_data):
        """Return host description."""
        return dict(host_desc=host_data['host_desc'])
    
    def build_vif(self, vif_data):
        """Return VIF description."""
        return dict(vif_desc=vif_data['vif_desc'])   
