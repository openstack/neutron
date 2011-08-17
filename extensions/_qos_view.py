def get_view_builder(req):
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for QoS, 
    derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, qos_data, is_detail=False):
        """Generic method used to generate a QoS entity."""
        print "qos_DATA:%s" % qos_data
        if is_detail:
            qos = self._build_detail(qos_data)
        else:
            qos = self._build_simple(qos_data)
        return qos
    
    def _build_simple(self, qos_data):
        """Return a simple model of a server."""
        return dict(qos=dict(id=qos_data['qos_id']))
    
    def _build_detail(self, qos_data):
        """Return a simple model of a server."""
        
        return dict(qos=dict(id=qos_data['qos_id'],
                                name=qos_data['qos_name'],
                                description=qos_data['qos_desc']))
