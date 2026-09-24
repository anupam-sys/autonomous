"""fully-autonomous: secret-exposure research pipeline.

Stages:
    1. discovery  — find repos / APKs / packages likely to leak secrets
    2. acquire    — download & decompile targets
    3. detect     — scan for exposed credentials, keys, URLs; triage & report
"""

__version__ = "0.1.0"
