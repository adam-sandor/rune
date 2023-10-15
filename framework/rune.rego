package rune

import future.keywords.in

rule_sets := data.rune.policy_bundle.rule_sets

results.rule_sets[rs_id] := r {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	r := {
		"name": rule_set.metadata.name,
		"result": result[rs_id],
		"reason": reason[rs_id],
		"result_validation_errors": result_validation_errors[rs_id],
	}
}

results.resolution_strategy := data.rune.policy_bundle.resolution_strategy

results.result := "allow" {
	final_allow
}

results.result := "deny" {
	not final_allow
}

final_allow {
	data.rune.policy_bundle.resolution_strategy == "default-deny"
	allows := {rs_id | some rs_id in rule_sets; results.rule_sets[rs_id].result == "allow"}
	count(allows) > 0
}

final_allow {
	data.rune.policy_bundle.resolution_strategy == "default-allow"
	denies := {rs_id | some rs_id in rule_sets; results.rule_sets[rs_id].result == "deny"}
	count(denies) == 0
}

result[rs_id] := "allow" {
	some rs_id in rule_sets
	allow[rs_id]
	count(result_validation_errors[rs_id]) == 0
}

result[rs_id] := "deny" {
	some rs_id in rule_sets
	not allow[rs_id]
	count(result_validation_errors[rs_id]) == 0
}

result[rs_id] := "error" {
	some rs_id in rule_sets
	count(result_validation_errors[rs_id]) > 0
}

enforced_allow[rs_id] := rule_results {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	rule_results := {res |
		some res in rule_set.allow
		enforce := object.get(res, "enforce", "enforce")
		enforce == "enforce"
	}
}

enforced_deny[rs_id] := rule_results {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	rule_results := {res |
		some res in rule_set.deny
		enforce := object.get(res, "enforce", "enforce")
		enforce == "enforce"
	}
}

result_validation_errors[rs_id] := errors {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	allow_results := {r | some r in rule_set.allow}
	deny_results := {r | some r in rule_set.deny}
	rule_results := allow_results | deny_results

	missing_id_errors := {error |
		some result in rule_results
		error := "Rule with missing name"
		keys := object.keys(result)
		not "id" in keys
	}
	errors := missing_id_errors
}

allow[rs_id] := true {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	rule_set.metadata.resolution_strategy == "default-deny-overrule"

	count(enforced_allow[rs_id]) > 0
	count(enforced_deny[rs_id]) == 0
}

allow[rs_id] := true {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	rule_set.metadata.resolution_strategy == "default-allow-overrule"

	count(enforced_deny[rs_id]) == 0
	count(enforced_allow[rs_id]) == 0
}

allow[rs_id] := true {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	rule_set.metadata.resolution_strategy == "default-deny"

	count(enforced_allow[rs_id]) > 0
}

allow[rs_id] := true {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	rule_set.metadata.resolution_strategy == "default-allow"

	count(enforced_deny[rs_id]) == 0
}

reason[rs_id] := r {
	some rs_id in rule_sets
	rule_set := data.policy[rs_id]
	r := {
		"resolution_strategy": rule_set.metadata.resolution_strategy,
		"enforced_allows": enforced_allow[rs_id],
		"enforced_denies": enforced_deny[rs_id],
	}
}
