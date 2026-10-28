package agentshield.authz_test

import rego.v1

import data.agentshield.authz

base := {"principal": {"subject": "u1", "roles": ["editor"], "scopes": [], "attrs": {"clearance": 2}}, "tool": {"name": "t", "effect": "read"}, "args": {}, "context": {}}

test_benign_read_allowed if authz.allow with input as base

test_empty_input_denied if not authz.allow with input as {}

test_large_transfer_denied_without_attr if {
	not authz.allow with input as object.union(base, {"tool": {"name": "t", "effect": "financial"}, "args": {"amount": 20000, "from_account": "a", "to_account": "b"}})
}

test_large_transfer_allowed_with_attr if {
	authz.allow with input as object.union(base, {"tool": {"name": "t", "effect": "financial"}, "args": {"amount": 20000, "from_account": "a", "to_account": "b"}, "principal": {"subject": "u1", "roles": [], "scopes": [], "attrs": {"finance_limit_ok": true}}})
}

test_self_transfer_denied if {
	not authz.allow with input as object.union(base, {"tool": {"name": "t", "effect": "financial"}, "args": {"amount": 1, "from_account": "a", "to_account": "a"}})
}

# object.union merges recursively, so `attrs: {}` would keep base's clearance; build these inputs explicitly.
test_exec_without_clearance_denied if {
	not authz.allow with input as {"principal": {"subject": "u1", "roles": [], "scopes": [], "attrs": {}}, "tool": {"name": "t", "effect": "exec"}, "args": {}, "context": {}}
}

test_exec_with_zero_clearance_denied if {
	not authz.allow with input as {"principal": {"subject": "u1", "roles": [], "scopes": [], "attrs": {"clearance": 0}}, "tool": {"name": "t", "effect": "exec"}, "args": {}, "context": {}}
}

test_exec_with_clearance_allowed if {
	authz.allow with input as object.union(base, {"tool": {"name": "t", "effect": "exec"}})
}

test_prod_offhours_delete_denied if {
	not authz.allow with input as object.union(base, {"tool": {"name": "t", "effect": "delete"}, "context": {"env": "prod", "hour_utc": 3}})
}

test_cross_tenant_denied if {
	not authz.allow with input as object.union(base, {"args": {"tenant": "b"}, "principal": {"subject": "u1", "roles": [], "scopes": [], "attrs": {"tenant": "a"}}})
}
