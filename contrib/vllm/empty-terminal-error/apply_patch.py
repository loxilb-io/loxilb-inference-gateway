#!/usr/bin/env python3
"""Apply only to the pinned vLLM 0.31.0 image build layer; fail on source drift."""
import hashlib,json,py_compile
from importlib.metadata import distribution
from pathlib import Path
OLD='''                        and not previous_num_tokens[i]
                    ):
                        # Chunked prefill case, don't return empty chunks
'''
NEW='''                        and not previous_num_tokens[i]
                        and output.finish_reason is None
                    ):
                        # Skip only empty in-progress prefill chunks; terminal
                        # errors and finish metadata must reach handling below.
'''
def transform(source,metadata):
 assert hashlib.sha256(source).hexdigest()==metadata['original_sha256'],'installed source drift'
 assert source.count(OLD.encode())==1,'gate not unique'
 result=source.replace(OLD.encode(),NEW.encode(),1)
 assert hashlib.sha256(result).hexdigest()==metadata['proposed_sha256'],'patched source drift'
 return result
if __name__=='__main__':
 pkg=distribution('vllm');assert pkg.version=='0.31.0'
 root=Path(__file__).resolve().parent;m=json.loads((root/'SOURCE.json').read_text())
 target=Path(pkg.locate_file('vllm/entrypoints/openai/chat_completion/serving.py'))
 target.write_bytes(transform(target.read_bytes(),m));py_compile.compile(str(target),doraise=True)
 (root/'BUILD-PROVENANCE.json').write_text(json.dumps({'vllm':pkg.version,'source_sha256':m['original_sha256'],'patched_sha256':m['proposed_sha256'],'path':str(target)},indent=2))
