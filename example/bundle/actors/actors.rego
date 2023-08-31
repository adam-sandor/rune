package policy.actors

import future.keywords.in

metadata := {
	"name": "Access to Actors",
	"description": "Deny access to actors for users who are not fan of the actor",
	"resolution_strategy": "default-allow"
}

deny[result] {
    not input.subject.username in data.actor_data[input.resource].fans

    result := {
        "name": "D-ACT1",
        "msg": sprintf("%s isn't a fan of actor %s", [input.subject.username, input.resource])
    }
}
