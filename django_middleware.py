from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, Http404
# from common.crypto import rsa as crypto  # we might want to change the underlying crypto


class VerifySignatureMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.
        # Only called once when the web-server starts!

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # https://docs.djangoproject.com/en/1.11/topics/http/middleware/#process-view
        # verify the JSON B64 string. return None if it's fine, return an HTTPResponse with an error if not

        if not request.GET['user'] == 'c1':
            return HttpResponseForbidden()

        #if valid(request.blob, request.signature, request.user):
        #    return None
        #return HttpResponseForbidden
