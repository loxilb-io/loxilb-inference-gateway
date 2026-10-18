FROM vllm/vllm-openai@sha256:a4a4c0437bf7240089da5f08aa370c4aee17ae5290f7a3b468825ee26c4c3a6b
COPY SOURCE.json apply_patch.py /opt/igw-empty-terminal-error/
RUN python3 /opt/igw-empty-terminal-error/apply_patch.py
LABEL netlox.engine.patch="vllm031-empty-terminal-error-r1"
