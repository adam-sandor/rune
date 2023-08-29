package rune

import future.keywords.in

rule_sets := data.rune.policy_bundle.rule_sets

results[rs_id] := r {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    r := {
        "rule_set": rule_set.metadata.name,
        "result": result[rs_id],
        "reason": reason[rs_id]
        #"result_validation_errors": result_validation_errors[rule_set]
    }
}

result[rs_id] := "allow" {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    allow[rule_set]
    #count(result_validation_errors) == 0
}

result[rs_id] := "deny" {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    not allow[rule_set]
    #count(result_validation_errors) == 0
}
#result := "error" {
#    count(result_validation_errors) > 0
#}

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

#result_validation_errors["Rule with missing name"] {
#    rule_results := rs.allow | rs.deny
#    result := rule_results[_]
#    keys := object.keys(result)
#    not "name" in keys
#}

#result_validation_errors[error] {
#    rule_results := rs.allow | rs.deny
#    result := rule_results[_]
#    enforce := object.get(result, "enforce", "enforce")
#    not enforce in {"enforce", "ignore", "monitor"}
#    error := sprintf("Invalid value for enforce property of rule %s: %s", [result.name, result.enforce])
#}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-deny-overrule"

    count(enforced_allow[rule_set]) > 0
    count(enforced_deny[rule_set]) == 0
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-allow-overrule"

    count(enforced_deny[rule_set]) == 0
    count(enforced_allow[rule_set]) == 0
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-deny"

    count(enforced_allow[rule_set]) > 0
}

allow[rs_id] := true {
    rs_id := rule_sets[_]
    rule_set := data.policy[rs_id]
    rule_set.metadata.resolution_strategy == "default-allow"

    count(enforced_deny[rule_set]) == 0
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