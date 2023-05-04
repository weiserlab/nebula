import json
from locust import HttpUser, task, between, events
import random
import resource
from token_gen import get_token
resource.setrlimit(resource.RLIMIT_NOFILE, (999999, 999999))

import json
from locust import HttpUser, task, between

with open('../keypair.bin', 'rb') as f:
    keypair = f.read()
num_tokens = 20000
tokens_per_req = 700
tokens_list = [get_token(keypair) for x in range(num_tokens)]

class TokenRedemption(HttpUser):
    wait_time = between(1, 2)

    @task
    def redeem_tokens(self):
        headers = {
            'Content-Type': 'application/json',
        }

        start_index = random.randint(0, num_tokens - tokens_per_req)
        sampled_tokens = tokens_list[start_index:start_index + tokens_per_req]

        data = {
            # 'tokens': ['ztuAgIfPmgZMpZcarGRwQXfuTpAPuRXIU5LUNdVQMr3Y9YlgwJIwueNYqU3cnibdXQzTHB/J/YcV26iB49i+Uw==' for x in range(tokens_per_req)]
            # 'tokens': [get_token(keypair) for x in range(tokens_per_req)]
            'tokens':sampled_tokens
        }

        self.client.post(
            '/redeem_tokens',
            headers=headers,
            data=json.dumps(data),
            verify=False,
        )
