## What and why

## Security checklist
- [ ] No secret, token, key or `.env` content is included
- [ ] New code paths fail closed (error/timeout/missing dependency => deny, not allow)
- [ ] Tests added: one that passes on the intended behaviour and one that proves the bypass is blocked
- [ ] `make test` and `make policy` pass locally
- [ ] Docs / threat-model entries updated if a trust boundary changed
