"""Execute the installed-source AST gate with six semantic controls."""
import ast,json,unittest
from pathlib import Path
from types import SimpleNamespace
from apply_patch import transform
class GateTests(unittest.TestCase):
 def test_exact_source_and_six_controls(self):
  import sys
  original=Path(sys.argv[1]).read_bytes()
  patched=transform(original,json.loads(Path(__file__).with_name('SOURCE.json').read_text()))
  def gate(src):
   tree=ast.parse(src);nodes=[n for n in ast.walk(tree) if isinstance(n,ast.If) and 'not previous_num_tokens[i]' in ast.unparse(n.test) and 'not output.token_ids' in ast.unparse(n.test)]
   self.assertEqual(len(nodes),1);return compile(ast.Expression(nodes[0].test),'<actual-vllm-gate>','eval')
  before,after=gate(original),gate(patched)
  cases=[('',[],0,None,True,True),('',[],0,'error',True,False),('',[],0,'stop',True,False),('',[],0,'length',True,False),('hello',[1],0,None,False,False),('',[],1,'error',False,False)]
  for text,tokens,prev,finish,old,new in cases:
   scope=dict(delta_text=text,output=SimpleNamespace(token_ids=tokens,finish_reason=finish),previous_num_tokens=[prev],i=0)
   self.assertEqual(bool(eval(before,scope)),old);self.assertEqual(bool(eval(after,scope)),new)
  with self.assertRaises(AssertionError):transform(patched,json.loads(Path(__file__).with_name('SOURCE.json').read_text()))
if __name__=='__main__':
 import sys
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(GateTests)
 result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
