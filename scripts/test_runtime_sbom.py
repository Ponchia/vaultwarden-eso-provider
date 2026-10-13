"""Locked Cargo inventory and privacy regression tests."""
import copy
import json
import struct
import unittest
from runtime_sbom import REGISTRY, generate


class RuntimeSbomTests(unittest.TestCase):
    def setUp(self):
        self.binary = bytearray(64)
        self.binary[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H',self.binary,18,62)
        self.metadata = {'packages':[
            {'id':'path+/private/person/project','name':'vaultwarden-eso-provider','version':'0.5.0','source':None,'license':'Apache-2.0','authors':['private author']},
            {'id':'dep','name':'dep','version':'1.0.0','source':REGISTRY,'license':'MIT'},
            {'id':'dev','name':'dev','version':'1.0.0','source':REGISTRY,'license':'MIT'}],
            'resolve':{'nodes':[
                {'id':'path+/private/person/project','deps':[{'pkg':'dep','dep_kinds':[{'kind':None}]},{'pkg':'dev','dep_kinds':[{'kind':'dev'}]}]},
                {'id':'dep','deps':[]},{'id':'dev','deps':[]}]}}
        self.lock = {'package':[{'name':'dep','version':'1.0.0','source':REGISTRY,'checksum':'c'*64}]}

    def build(self):
        return generate(self.metadata,self.lock,bytes(self.binary),'amd64','a'*40)

    def test_graph_has_binary_and_no_dev_dependency(self):
        result = self.build()
        self.assertEqual(len(result['packages']),3)
        self.assertEqual({p['name'] for p in result['packages']},{'vaultwarden-eso-provider','dep'})
        self.assertEqual(len(result['relationships']),3)

    def test_no_private_cargo_paths_or_authors(self):
        serialized = json.dumps(self.build())
        self.assertNotIn('/private/',serialized)
        self.assertNotIn('private author',serialized)

    def test_locked_checksum_is_required(self):
        self.lock['package'][0]['checksum'] = None
        with self.assertRaises(ValueError): self.build()

    def test_unsupported_git_dependency_fails(self):
        self.metadata['packages'][1]['source'] = 'git+https://example.invalid/unreviewed'
        with self.assertRaises(ValueError): self.build()

    def test_incomplete_graph_fails(self):
        self.metadata['resolve']['nodes'].pop(1)
        with self.assertRaises(ValueError): self.build()

    def test_build_only_dependency_is_excluded(self):
        self.metadata['resolve']['nodes'][0]['deps'][0]['dep_kinds'][0]['kind'] = 'build'
        self.assertEqual(len(self.build()['packages']),2)

    def test_mixed_normal_and_dev_dependency_is_included(self):
        self.metadata['resolve']['nodes'][0]['deps'][0]['dep_kinds'].append({'kind':'dev'})
        self.assertEqual(len(self.build()['packages']),3)

    def test_wrong_executable_platform_is_rejected(self):
        struct.pack_into('<H',self.binary,18,183)
        with self.assertRaises(ValueError): self.build()


if __name__ == '__main__': unittest.main()
