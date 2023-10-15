package rune

import future.keywords.in

rule_sets := data.rune.policy_bundle.rule_sets

results["rule_sets"] := rule_sets

results[rs_id] := r {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    r := {
        "name": rule_set.metadata.name,
        "result": result[rs_id],
        "reason": reason[rs_id],
        "result_validation_errors": result_validation_errors[rs_id]
    }
}
results["resolution_strategy"] := data.rune.policy_bundle.resolution_strategy

results["result"] := "allow" {
    final_allow
}

results["result"] := "deny" {
    not final_allow
}

final_allow := true {
    data.rune.policy_bundle.resolution_strategy == "default-deny"
    allows := { rs_id | rs_id := rule_sets[_]; results[rs_id].result == "allow" }
    count(allows) > 0
}

final_allow := true {
    data.rune.policy_bundle.resolution_strategy == "default-allow"
    denies := { rs_id | rs_id := rule_sets[_]; results[rs_id].result == "deny" }   
    count(denies) == 0
}

result[rs_id] := "allow" {
    rs_id := rule_sets[_]
    allow[rs_id]
    count(result_validation_errors[rs_id]) == 0
}
result[rs_id] := "deny" {
    rs_id := rule_sets[_]
    not allow[rs_id]
    count(result_validation_errors[rs_id]) == 0
}
result[rs_id] := "error" {
    rs_id := rule_sets[_]
    count(result_validation_errors[rs_id]) > 0
}

enforced_allow[rs_id] := rule_results {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_results := { res | res := rule_set.allow[_];
        enforce := object.get(res, "enforce", "enforce");
        enforce == "enforce" }
}
enforced_deny[rs_id] := rule_results {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_results := { res | res := rule_set.deny[_];
        enforce := object.get(res, "enforce", "enforce");
        enforce == "enforce" }
}

result_validation_errors[rs_id] := errors {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    allow_results := { r | r := rule_set.allow[_] }
    deny_results := { r | r := rule_set.deny[_] }
    rule_results := allow_results | deny_results

    missing_id_errors := { error |
        result := rule_results[_];
        error := "Rule with missing name";
        keys := object.keys(result)
        not "id" in keys }
    errors := missing_id_errors
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-deny-overrule"

    count(enforced_allow[rs_id]) > 0
    count(enforced_deny[rs_id]) == 0
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-allow-overrule"

    count(enforced_deny[rs_id]) == 0
    count(enforced_allow[rs_id]) == 0
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-deny"

    count(enforced_allow[rs_id]) > 0
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-allow"

    count(enforced_deny[rs_id]) == 0
}

reason[rs_id] := r {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    r := {
        "resolution_strategy": rule_set.metadata.resolution_strategy,
        "enforced_allows": enforced_allow[rs_id],
        "enforced_denies": enforced_deny[rs_id],
    }
}