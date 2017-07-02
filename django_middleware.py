from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseServerError
import json

from common.crypto import rsa as crypto  # we might want to change the underlying crypto


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
        # verify the JSON B64 string. return None if it's fine,
        # return an HTTPResponse with an error if not

        if request.type == 'GET':
            return None  # No signature verification needed

        try:
            author, blob, signature = request.POST['author'], request.POST['blob'], request.POST['signature']
        except KeyError:
            return HttpResponseBadRequest()

        # get user pubkey
        # what if the author CAN'T already be registered? i.e.: group key
        # maybe check view_func and ignore a few?
        # or let the view itself verify if the author is registered...

        # NOTE: This does not verify if the signer is authorized for the operation.
        #       It only verifies if the signature matches the given pub key

        try:
            crypto.verify(author, blob, signature)
            return None
        except crypto.InvalidSignature:
            return HttpResponseForbidden()
            # or 401 Unauthorized...
