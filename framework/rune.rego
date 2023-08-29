package rune

import future.keywords.in

results["result"] := result
results["reason"] := reason
results["result_validation_errors"] := result_validation_errors

result := "allow" {
    allow
    count(result_validation_errors) == 0
}
result := "deny" {
    not allow
    count(result_validation_errors) == 0
}
result := "error" {
    count(result_validation_errors) > 0
}

enforced_allow[rule_result] {
    rule_result := rs.allow[_]
    enforce := object.get(rule_result, "enforce", "enforce")
    enforce == "enforce"
}
enforced_deny[rule_result] {
    rule_result := rs.deny[_]
    enforce := object.get(rule_result, "enforce", "enforce")
    enforce == "enforce"
}

result_validation_errors["Rule with missing name"] {
    rule_results := rs.allow | rs.deny
    result := rule_results[_]
    keys := object.keys(result)
    not "name" in keys
}

result_validation_errors[error] {
    rule_results := rs.allow | rs.deny
    result := rule_results[_]
    enforce := object.get(result, "enforce", "enforce")
    not enforce in {"enforce", "ignore", "monitor"}
    error := sprintf("Invalid value for enforce property of rule %s: %s", [result.name, result.enforce])
}

allow {
    rs.rule_set.resolution_strategy == "default-deny-overrule"

    count(enforced_allow) > 0
    count(enforced_deny) == 0
}

allow {
    rs.rule_set.resolution_strategy == "default-allow-overrule"

    count(enforced_deny) == 0
    count(enforced_allow) == 0
}

allow {
    rs.rule_set.resolution_strategy == "default-deny"

    count(enforced_allow) > 0
}

allow {
    rs.rule_set.resolution_strategy == "default-allow"

    count(enforced_deny) == 0
}

reason["resolution_strategy"] := rs.rule_set.resolution_strategy

reason["enforced_allows"] := enforced_allow {
    #only list applied allows if the overall result is allow
    allow
}

reason["enforced_denies"] := enforced_deny {
    #only list applied denies if the overall result is deny
    not allow
}