package rune

test_single_rule_set {
    results with input as {
        "resources": {
            "movie": "movies/124442"
        },
        "action": "read",
        "subject": {
            "username": "adam.sandor",
            "fullname": "Adam Sandor",
            "groups": ["movie-readers", "lion-tamers"]
        }
    } with data.rune.policy_bundle as {
        "name": "movies",
        "rule_sets": [
            "movies"
        ],
        "resolution_strategy": "default-allow"
    }
}