def get_view_builder(req):
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for Credential, 
    derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, credential_data, is_detail=False):
        """Generic method used to generate a credential entity."""
        print "credential-DATA:%s" % credential_data
        if is_detail:
            credential = self._build_detail(credential_data)
        else:
            credential = self._build_simple(credential_data)
        return credential
    
    def _build_simple(self, credential_data):
        """Return a simple model of a server."""
        return dict(credential=dict(id=credential_data['credential_id']))
    
    def _build_detail(self, credential_data):
        """Return a simple model of a server."""
        
        return dict(credential=dict(id=credential_data['credential_id'],
                                name=credential_data['user_name'],
                                password=credential_data['password']))