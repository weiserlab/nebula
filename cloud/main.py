# main.py

from fastapi import FastAPI, Request, HTTPException, Response # type: ignore
import inspect
import os
import threading
from typing import Any, Dict

import appserver # Assuming app.py is in the same directory
import provider  # Assuming provider.py is in the same directory


app = FastAPI()
mode = os.environ.get('SERVER_MODE') 


class FunctionThread(threading.Thread):
    def __init__(self, target, args=(), kwargs=None):
        super().__init__()
        self.target = target
        self.args = args
        self.kwargs = kwargs if kwargs else {}
        self.result = None

    def run(self):
        self.result = self.target(*self.args, **self.kwargs)


async def make_threaded_call(request: Request, fn):

    params = dict(request.query_params)
    body_bytes = await request.body()

    print(f'Calling {fn.__name__} with params {params} and body {body_bytes}')

    def call_function_threaded():
        return fn(**params, payload=body_bytes)

    thread = FunctionThread(target=call_function_threaded)
    thread.start()
    thread.join()

    if thread.result is None:
        raise HTTPException(status_code=500, detail=f'{mode} error')

    return Response(content=thread.result, media_type='application/octet-stream')


@app.get('/')
async def root():
    return {'status': f'{mode} running'}

if mode == 'provider':

    @app.get('/public_params')
    async def public_params(request: Request):
        return await make_threaded_call(request, provider.get_public_params)

    @app.post('/sign_tokens')
    async def sign_tokens(request: Request):

        print(f"Method: {request.method}")
        print(f"URL: {request.url}")
        print(f"Headers: {request.headers}")
        print(f"Query parameters: {request.query_params}")
        print(f"Path parameters: {request.path_params}")
        print(f"Cookies: {request.cookies}")
        print(f"Client host: {request.client.host}")
        print(f"Client port: {request.client.port}")
        print(f"Path: {request.url.path}")
        print(f"Scheme: {request.url.scheme}")
        print(f"Body: {await request.body()}")
        
        return await make_threaded_call(request, provider.sign_tokens)

    @app.post('/redeem_tokens')
    async def redeem_tokens(request: Request):
        return await make_threaded_call(request, provider.redeem_tokens)

    @app.get('/complaint_public_params')
    async def complaint_public_params(request: Request):
        return await make_threaded_call(request, provider.get_complaint_public_params)

    @app.post('/complain')
    async def complain(request: Request):
        return await make_threaded_call(request, provider.complain)

    @app.post('/new_epoch')
    async def new_epoch(request: Request):
        return await make_threaded_call(request, provider.new_epoch)

elif mode == 'app':

    @app.post('/deliver_hash')
    async def deliver_hash(request: Request):
        return await make_threaded_call(request, appserver.deliver_hash_payload)

    @app.post('/deliver_data')
    async def deliver(request: Request):
        return await make_threaded_call(request, appserver.deliver_data)

    @app.post('/deliver_complaint_data')
    async def deliver_complaint_data(request: Request):
        return await make_threaded_call(request, appserver.deliver_complaint_data)

