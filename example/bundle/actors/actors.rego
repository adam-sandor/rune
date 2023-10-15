package policy.actors

import future.keywords.in

metadata := {
	"name": "Access to Actors",
	"description": "Deny access to actors for users who are not fans of the actor",
	"resolution_strategy": "default-deny"
}

allow[result] {
    "actor-editors" in input.subject.groups
    regex.match("actors/\\d+", input.resources.actor)
    input.action in {"add", "remove"}

    result := {
        "id": "A-ACT1",
        "msg": sprintf("%s can add and remove actors from movies", [input.subject.username])
    }
}
