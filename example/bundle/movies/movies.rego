package example.movies

import future.keywords.in

rule_set := {
	"name": "Access to Movies",
	"description": "Grant access to movies for movie-readers",
	"resolution_strategy": "default-deny-overrule",
}

allow[result] {
    "movie-readers" in input.subject.groups
    regex.match("movies/\\d+", input.resource)
    input.action == "read"

    result := {
    	"name": "A-MR1",
        "msg": sprintf("%s is allowed to read %s because part of movie-readers group",
        	[input.subject.username, input.resource]),
    }
}

deny[result] {

	input.subject.username == "adam.sandor"
    input.action == "read"
    input.resource == "movies/124442"

    result := {
    	"name": "D-MR2",
        "msg": "adam.sandor is not allowed to read movies/124442",
        "enforce": "enforce"
    }
}