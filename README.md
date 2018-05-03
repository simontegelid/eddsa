# Edwards-Curve Digital Signature Algorithm (EdDSA)

Based on Appendix A and B in RFC 8032 (https://tools.ietf.org/html/rfc8032)

## Usage
```python
from binascii import unhexlify as uh

import eddsa

prv = uh("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
pub = uh("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
msg = b"foobar"

ed = eddsa.Ed25519()

# Sign a message
sig = ed.sign(prv, pub, msg)

# Verify a signature
ed.verify(pub, msg, sig)

# Generate a keypair if you don't have one
prv, pub = ed.keygen()
```
