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
        print "portprofile_DATA:%s" % portprofile_data
        if is_detail:
            portprofile = self._build_detail(portprofile_data)
        else:
            portprofile = self._build_simple(portprofile_data)
        return portprofile
    
    def _build_simple(self, portprofile_data):
        """Return a simple model of a portprofile"""
        return dict(portprofile=dict(id=portprofile_data['profile_id']))
    
    def _build_detail(self, portprofile_data):
        """Return a detailed info of a portprofile."""
        if (portprofile_data['assignment'] == None):
            return dict(portprofile=dict(id=portprofile_data['profile_id'],
                                name=portprofile_data['profile_name'],
                                qos_name=portprofile_data['qos_name']))
        else:
            return dict(portprofile=dict(id=portprofile_data['profile_id'],
                                name=portprofile_data['profile_name'],
                                qos_name=portprofile_data['qos_name'],
                                assignment=portprofile_data['assignment']))
