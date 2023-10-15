package rune

test_single_rule_set_default_allow_strategy_deny_result {
	r := results with input as {
		"resources": {"movie": "movies/124442"},
		"action": "read",
		"subject": {
			"username": "adam.sandor",
			"fullname": "Adam Sandor",
			"groups": ["movie-readers", "lion-tamers"],
		},
	}
		with data.rune.policy_bundle as {
			"name": "movies",
			"rule_sets": ["movies", "actors"],
			"resolution_strategy": "default-allow",
		}

	r.result == "deny"
	r.rule_sets.movies.result == "deny"
}

test_multiple_rule_set_default_allow_strategy_allow_result {
	r := results with input as {
		"resources": {
			"movie": "movies/224333",
			"actor": "actors/338",
		},
		"action": "add",
		"subject": {
			"username": "adam.sandor",
			"fullname": "Adam Sandor",
			"groups": ["movie-readers", "lion-tamers", "movie-editors", "actor-editors"],
		},
	}
		with data.rune.policy_bundle as {
			"name": "movies-and-actors",
			"rule_sets": [
				"actors",
				"movies",
			],
			"resolution_strategy": "default-allow",
		}

	r.result == "allow"
	r.rule_sets.movies.result == "allow"
	r.rule_sets.actors.result == "allow"
}
