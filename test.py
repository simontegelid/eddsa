#!/usr/bin/env python
import unittest
from binascii import unhexlify as uh

import eddsa


class TestEd25519(unittest.TestCase):

    def test_1(self):
        prv = uh("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pub = uh("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        ctx = uh("")
        msg = uh("")
        sig = uh("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

        ed = eddsa.Ed25519()

        self.assertEqual(ed.sign(prv, pub, msg), sig)
        self.assertNotEqual(ed.sign(prv, pub, b"foobar"), sig)


if __name__ == '__main__':
    unittest.main()
