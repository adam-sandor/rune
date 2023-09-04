package policy.movies

import future.keywords.in

metadata := {
	"name": "Access to Movies",
	"description": "Grant access to movies for movie-readers",
	"resolution_strategy": "default-deny-overrule",
}

allow[result] {
    "movie-readers" in input.subject.groups
    regex.match("movies/\\d+", input.resources.movie)
    input.action == "read"

    result := {
    	"id": "A-MR1",
        "msg": sprintf("%s is allowed to read %s because part of movie-readers group",
        	[input.subject.username, input.resource]),
    }
}

allow[result] {
    "movie-editors" in input.subject.groups
    regex.match("movies/\\d+", input.resources.movie)
    input.action in {"edit", "remove", "add"}
    print("X")

    result := {
    	"id": "A-E-MR3",
        "msg": sprintf("%s is allowed to edit %s because part of movie-editors group",
        	[input.subject.username, input.resources.movie]),
    }
}

deny[result] {
	input.subject.username == "adam.sandor"
    input.resources.movie == "movies/124442"

    result := {
    	"id": "D-MR2",
        "msg": "adam.sandor is not allowed to read or edit movie 124442",
        "enforce": "enforce"
    }
}
