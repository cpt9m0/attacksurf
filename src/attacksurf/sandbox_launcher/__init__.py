"""`sandbox-launcher`: turns "run analyzer X on artifact Y" into one sandbox (ADR 0016).

It holds no app secrets and never touches the Docker socket; it only talks to `sandbox-proxy`.
"""
