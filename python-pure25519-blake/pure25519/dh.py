from pure25519.basic import random_scalar, Base, bytes_to_element
#from hashlib import sha256
from pyblake2 import blake2b

# In practice, you should use the Curve25519 function, which is better in
# every way. But this is an example of what Diffie-Hellman looks like.

def dh_start(entropy_f):
    x = random_scalar(entropy_f)
    X = Base.scalarmult(x)
    return x,X.to_bytes()

def dh_finish(x, Y_s):
    Y = bytes_to_element(Y_s)
    XY = Y.scalarmult(x)
    return blake2b(XY.to_bytes()).digest()
