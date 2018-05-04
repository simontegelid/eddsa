#!/usr/bin/env python
import unittest
from binascii import unhexlify as uh
import hashlib

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
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar"), sig)
        self.assertTrue(ed.verify(pub, msg, sig))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_2(self):
        prv = uh("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pub = uh("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        ctx = uh("")
        msg = uh("72")
        sig = uh("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")

        ed = eddsa.Ed25519()

        self.assertEqual(ed.sign(prv, pub, msg), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar"), sig)
        self.assertTrue(ed.verify(pub, msg, sig))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_3(self):
        prv = uh("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
        pub = uh("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        ctx = uh("")
        msg = uh("af82")
        sig = uh("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")

        ed = eddsa.Ed25519()

        self.assertEqual(ed.sign(prv, pub, msg), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar"), sig)
        self.assertTrue(ed.verify(pub, msg, sig))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_1024(self):
        prv = uh("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5")
        pub = uh("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e")
        ctx = uh("")
        msg = uh("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0")
        sig = uh("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03")

        ed = eddsa.Ed25519()

        self.assertEqual(ed.sign(prv, pub, msg), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar"), sig)
        self.assertTrue(ed.verify(pub, msg, sig))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_sha_abc(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        pub = uh("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        ctx = uh("")
        msg = hashlib.sha512(b"abc").digest()
        sig = uh("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")

        ed = eddsa.Ed25519()

        self.assertEqual(ed.sign(prv, pub, msg), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar"), sig)
        self.assertTrue(ed.verify(pub, msg, sig))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig))
        self.assertEqual(ed.keygen(prv), (prv, pub))


class TestEd25519ctx(unittest.TestCase):

    def test_foo(self):
        prv = uh("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")
        pub = uh("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")
        ctx = uh("666f6f")
        msg = uh("f726936d19c800494e3fdaff20b276a8")
        sig = uh("55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d")

        ed = eddsa.Ed25519ctx()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))


class TestEd25519ph(unittest.TestCase):

    def test_abc(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        pub = uh("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        ctx = uh("")
        msg = uh("616263")
        sig = uh("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")

        ed = eddsa.Ed25519ph()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_abc_update(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        pub = uh("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        ctx = uh("")
        sig = uh("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")

        ed = eddsa.Ed25519ph()

        ed.update(b'\x61')
        ed.update(b'\x62')
        self.assertEqual(ed.sign(prv, pub, b'\x63', ctx), sig)

    def test_abc_update2(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        pub = uh("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        ctx = uh("")
        sig = uh("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")

        ed = eddsa.Ed25519ph()

        ed.update(b'')
        ed.update(b'\x61')
        ed.update(b'')
        ed.update(b'\x62')
        ed.update(b'\x63')
        self.assertEqual(ed.sign(prv, pub, b'', ctx), sig)

    def test_abc_update3(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        pub = uh("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        ctx = uh("")
        sig = uh("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")

        ed = eddsa.Ed25519ph()

        ed.update(b'\x61')
        ed.update(b'\x62')
        self.assertTrue(ed.verify(pub, b'\x63', sig, ctx))

    def test_abc_update4(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        pub = uh("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        ctx = uh("")
        sig = uh("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")

        ed = eddsa.Ed25519ph()

        ed.update(b'')
        ed.update(b'\x61')
        ed.update(b'')
        ed.update(b'\x62')
        ed.update(b'\x63')
        self.assertTrue(ed.verify(pub, b'', sig, ctx))


class TestEd448(unittest.TestCase):

    def test_blank(self):
        prv = uh("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")
        pub = uh("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180")
        ctx = uh("")
        msg = uh("")
        sig = uh("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600")

        ed = eddsa.Ed448()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_1_octet(self):
        prv = uh("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e")
        pub = uh("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480")
        ctx = uh("")
        msg = uh("03")
        sig = uh("26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00")

        ed = eddsa.Ed448()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_1_octet_with_context(self):
        prv = uh("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e")
        pub = uh("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480")
        ctx = uh("666f6f")
        msg = uh("03")
        sig = uh("d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00")

        ed = eddsa.Ed448()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))


class TestEd448ph(unittest.TestCase):

    def test_abc(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")
        pub = uh("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")
        ctx = uh("")
        msg = uh("616263")
        sig = uh("822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00")

        ed = eddsa.Ed448ph()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))

    def test_abc_update(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")
        pub = uh("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")
        ctx = uh("")
        sig = uh("822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00")

        ed = eddsa.Ed448ph()

        ed.update(b'\x61')
        ed.update(b'\x62')
        self.assertEqual(ed.sign(prv, pub, b'\x63', ctx), sig)

    def test_abc_update2(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")
        pub = uh("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")
        ctx = uh("")
        sig = uh("822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00")

        ed = eddsa.Ed448ph()

        ed.update(b'')
        ed.update(b'\x61')
        ed.update(b'')
        ed.update(b'\x62')
        ed.update(b'\x63')
        self.assertEqual(ed.sign(prv, pub, b'', ctx), sig)

    def test_abc_update3(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")
        pub = uh("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")
        ctx = uh("")
        sig = uh("822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00")

        ed = eddsa.Ed448ph()

        ed.update(b'\x61')
        ed.update(b'\x62')
        self.assertTrue(ed.verify(pub, b'\x63', sig, ctx))

    def test_abc_update4(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")
        pub = uh("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")
        ctx = uh("")
        sig = uh("822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00")

        ed = eddsa.Ed448ph()

        ed.update(b'')
        ed.update(b'\x61')
        ed.update(b'')
        ed.update(b'\x62')
        ed.update(b'\x63')
        self.assertTrue(ed.verify(pub, b'', sig, ctx))

    def test_abc_with_context(self):
        prv = uh("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")
        pub = uh("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")
        ctx = uh("666f6f")
        msg = uh("616263")
        sig = uh("c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100")

        ed = eddsa.Ed448ph()

        self.assertEqual(ed.sign(prv, pub, msg, ctx), sig)
        self.assertNotEqual(ed.sign(prv, pub, msg + b"foobar", ctx), sig)
        self.assertTrue(ed.verify(pub, msg, sig, ctx))
        self.assertFalse(ed.verify(pub, msg + b"foobar", sig, ctx))
        self.assertEqual(ed.keygen(prv), (prv, pub))


if __name__ == '__main__':
    unittest.main()
