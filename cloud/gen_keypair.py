# Generate a keypair for the provider. Run this script once to generate a
# `keypair.bin` file, but don't commit to the repo.

import tokenlib

keypair = tokenlib.generate_keypair()

with open('keypair.bin', 'wb') as f:
    f.write(keypair)

with open('complaints-keypair.bin', 'wb') as f:
    f.write(keypair)
