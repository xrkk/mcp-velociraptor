"""Complete code-owned coordinate layouts; no file-path translation."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from tests import p05_pc020_evidence as pc, p05_baseline_adoption as adoption


class SourceLayouts(unittest.TestCase):
    def originals(self, root, paths):
        rows=[];policy={}
        for name in sorted(paths):
            data=('immutable '+name+'\n').encode()
            path=root/'source'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            sha=hashlib.sha256(data).hexdigest();blob=pc._blob(data)
            rows.append(dict(repo_path=name,blob=blob,content=dict(path='source/'+name,size=len(data),sha256=sha)))
            policy[name]=pc.FrozenIdentity(len(data),sha,blob)
        return rows,policy

    def test_both_complete_pc020_layouts_read_original_coordinates(self):
        for paths in (pc.PC020_HISTORICAL_SOURCE_PATHS,pc.PC020_CURRENT_SOURCE_PATHS):
            with self.subTest(layout=paths),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);rows,policy=self.originals(root,paths)
                self.assertEqual(len(pc._source_layout(set(policy))),34)
                self.assertEqual(set(pc._sources(root,rows,policy,'source_inputs',{})),paths)

    def test_both_complete_adoption_layouts_read_original_coordinates(self):
        for paths in (adoption.ADOPTION_HISTORICAL_SOURCE_PATHS,adoption.ADOPTION_CURRENT_SOURCE_PATHS):
            with self.subTest(layout=paths),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);rows,_=self.originals(root,paths)
                adoption._verify_sources(root,rows,{})
                self.assertEqual(len(paths),12)

    def test_complete_set_guard_rejects_mixed_subset_extra_alias(self):
        for module,prefix in ((pc,'PC020'),(adoption,'ADOPTION')):
            historical=getattr(module,prefix+'_HISTORICAL_SOURCE_PATHS')
            current=getattr(module,prefix+'_CURRENT_SOURCE_PATHS')
            pairs=getattr(module,prefix+'_NAVIGATION_COORDINATES')
            for old,new in pairs.items():
                with self.subTest(prefix=prefix,path=old):
                    with self.assertRaises(ValueError):module._source_layout((set(historical)-{old})|{new})
                    with self.assertRaises(ValueError):module._source_layout((set(current)-{new})|{old})
            first=next(iter(historical))
            for invalid in (set(historical)-{first},set(historical)|{'extra'},(set(historical)-{first})|{'./'+first}):
                with self.assertRaises(ValueError):module._source_layout(invalid)

    def test_actual_source_identity_missing_duplicate_blob_bytes_ref_and_bool(self):
        for module,paths in ((pc,pc.PC020_HISTORICAL_SOURCE_PATHS),(adoption,adoption.ADOPTION_HISTORICAL_SOURCE_PATHS)):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);rows,policy=self.originals(root,paths)
                def check(value):
                    if module is pc:module._sources(root,value,policy,'source_inputs',{})
                    else:module._verify_sources(root,value,{})
                mutations=(lambda r:r.pop(),lambda r:r.append(copy.deepcopy(r[0])),
                    lambda r:r[0].update(blob='0'*40),lambda r:r[0]['content'].update(size=True),
                    lambda r:r[0]['content'].update(sha256='0'*64),
                    lambda r:r[0]['content'].update(path='source/../outside'),
                    lambda r:r[0].update(repo_path='./'+r[0]['repo_path']))
                for mutate in mutations:
                    altered=copy.deepcopy(rows);mutate(altered)
                    with self.subTest(module=module.__name__,rows=altered[0]):
                        with self.assertRaises(ValueError):check(altered)
                path=root/rows[0]['content']['path'];data=path.read_bytes();path.write_bytes(data+b'actor')
                with self.assertRaises(ValueError):check(rows)
                path.unlink()
                with self.assertRaises(ValueError):check(rows)
                # No fallback to a current same-leaf file exists.

    def test_trusted_bool_identity_is_not_integer_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rows,policy=self.originals(root,pc.PC020_HISTORICAL_SOURCE_PATHS)
            first=rows[0]['repo_path'];value=policy[first]
            policy[first]=pc.FrozenIdentity(True,value.sha256,value.blob)
            with self.assertRaisesRegex(ValueError,'trusted identity is invalid'):
                pc._sources(root,rows,policy,'source_inputs',{})


if __name__=='__main__':unittest.main()
