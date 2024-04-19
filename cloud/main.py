# main.py

from fastapi import FastAPI, Request, HTTPException
import inspect
import os
import threading
from typing import Any, Dict

import appserver # Assuming app.py is in the same directory
import provider  # Assuming provider.py is in the same directory


app = FastAPI()
mode = os.environ.get("SERVER_MODE") 


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
    body_json = None
    try: 
        body_json = await request.json()
    except Exception as e:
        print("Error parsing body: {}".format(e))
        #print(request.text())

    def call_function_threaded():
        return fn(**params, payload=body_json)

    thread = FunctionThread(target=call_function_threaded)
    thread.start()
    thread.join()

    return {"result": thread.result}

@app.get("/")
async def root():
    return {"status": f"{mode} running"}

if mode == "provider":

    @app.get("/public_params")
    async def public_params(request: Request):
        return await make_threaded_call(request, provider.get_public_params)

    @app.post("/sign_tokens")
    async def sign_tokens(request: Request):
        return await make_threaded_call(request, provider.sign_tokens)

    @app.post("/redeem_tokens")
    async def redeem_tokens(request: Request):
        return await make_threaded_call(request, provider.redeem_tokens)

    @app.post("/query_provider")
    async def query_provider(request: Request):
        return await make_threaded_call(request, provider.query_provider)

    @app.post("/complain")
    async def complain(request: Request):
        return await make_threaded_call(request, provider.complain)

    @app.get("/complaint_public_params")
    async def complaint_public_params(request: Request):
        return await make_threaded_call(request, provider.get_complaint_public_params)

elif mode == "app":

    @app.post("/deliver")
    async def deliver(request: Request):
        return await make_threaded_call(request, appserver.deliver)

    @app.post("/pre_deliver")
    async def pre_deliver(request: Request):
        return await make_threaded_call(request, appserver.pre_deliver)
