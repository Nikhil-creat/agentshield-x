# AgentShield-X — OPA authorization policy (defence in depth behind the in-process ABAC rules).
# Endpoint queried by the engine: POST /v1/data/agentshield/authz/allow   (see OpaClient)
# Input: {principal:{subject,roles,scopes,attrs}, tool:{name,effect}, args:{}, context:{}}
# Deny-by-default: `allow` is true only when no deny rule fires.  Any OPA error/timeout => the engine denies.
#
# NOTE: written for OPA >= 0.59 (rego.v1). Validate with:  opa test policies/rego -v   and   opa check --strict policies/rego
package agentshield.authz

import rego.v1

default allow := false

allow if {
	count(deny) == 0
	input.principal.subject != ""
}

deny contains "fin.limit: transfers over 10,000 require finance_limit_ok" if {
	input.tool.effect == "financial"
	input.args.amount > 10000
	not input.principal.attrs.finance_limit_ok == true
}

deny contains "fin.self: source and destination accounts must differ" if {
	input.tool.effect == "financial"
	input.args.from_account == input.args.to_account
}

deny contains "exec.clearance: code execution requires clearance >= 1" if {
	input.tool.effect == "exec"
	input.principal.attrs.clearance < 1
}

deny contains "exec.clearance: code execution requires a clearance attribute" if {
	input.tool.effect == "exec"
	not input.principal.attrs.clearance
}

deny contains "prod.offhours: destructive/financial actions blocked 00:00-06:00 UTC in prod" if {
	input.context.env == "prod"
	input.tool.effect in {"delete", "financial"}
	input.context.hour_utc < 6
}

deny contains "tenant.mismatch: cross-tenant access" if {
	input.principal.attrs.tenant
	input.args.tenant
	input.args.tenant != input.principal.attrs.tenant
}
