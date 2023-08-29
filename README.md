# ᛤ Rune Framework for Rego ᛤ

An opinionated framework designed to help build maintanable and well-structured Rego code.

It implements the following design patterns & functionality:

* Make evaluation strategies like "Allow by default or Deny by default" configurable without having to
restructure the code.
* Enforce naming rules for better auditing and debugging.
* Explain how an evaluation result was made using rule names and detail messages.
* Rules can be temporarily turned off or put into monitoring state without significant code change.
* Mixing of allow and deny rules with clear semantics for evaluation.

## Your code and Rune

Rune expects your Rego to be structured in a certain way (design patterns) to provide functionality. You as the
user win in two ways - you're code will be using best practices and you get a bunch of useful stuff out of the
box.

Here is a Rego rule in Rune format. The type of the rule (set of objects named `allow` or `deny`) 
is predefined as well as the result, which is an object that has 3 properties (only `enforce` is optional).
Your code is expected to be a series of such `allow` and `deny` rules in different packages.
```rego
allow[result] {

    "movie-readers" in input.subject.groups
    regex.match("movies/\\d+", input.resource)
    input.action == "read"

    result := {
    	"name": "A-MR1",
        "msg": sprintf("%s is allowed to read %s because part of movie-readers group",
        	[input.subject.username, input.resource]),
        "enforce": "ignore"
    }
}
```

## Rune's semantics

Rune expects an object called `rule_set` to be defined in the same package that provides the configuration.
This provides configurable strategy for evaluating the sets of `allow` and `deny` results.
```rego
rule_set := {
	"name": "Access to Movies",
	"resolution_strategy": "default-deny"
}
```

`name`: The name of the rule set. Optional as package name is used by default.

`resultion_strategy`: 
* `default-allow`: The final result is `allow` unless at least one `deny` rule evaluates to true
* `default-deny`: The final result is `deny` unless at least one `allow` rule evaluates to true
* `default-allow-overrule`: The final result is `allow` if a no `deny` rule is triggered or if an `allow` rule is 
triggered as well.
* `default-deny-overrule`: The final result is `deny` if a no `allow` rule is triggered or if an `deny` rule is
  triggered as well.

The first two strategies a pretty straight-forward, but the third and fourth need some explanation: They can be used
in cases where additionally to your "normal" rules you have some that are so important they override the final decision.

For example: No user can access the `/admin` endpoint unless they are part of the `administrator` group. However,
a user with a `suspicious_activity=true` attribute can't access the endpoint even if they are part of the group. 

This can be implemented using a `default-deny-overrule` strategy, an `allow` rule for the group check 
and a `deny` rule for the suspicious activity check. The user will be denied if the `allow` rule doesn't 
fire or if the `deny` rule does.

#### Rules 

Each rule has to be a set rule adding an object either the `allow` or `deny` sets in the package. The rule
result object has to have a `name`, a `msg` and an optional `enforce` property:

```rego
deny[result] {
	input.subject.username == "adam.sandor"
    input.action == "read"
    input.resource == "movies/124442"

    result := {
    	"name": "D-MR2",
        "msg": "adam.sandor is not allowed to read movies/124442",
        "enforce": "ignore"
    }
}
```

#### 

## Execution

Rune provides the entrypoint rule, so it can take over the evaluation process. Clients should invoke the
`rune.results` rule:
```shell
opa eval data.rune.results --bundle ./ -i example/input.json
```

The results from Rune look like this:
```json
{
  "result": "deny",
  "reason": {
    "applied_allows": [
      {"name": "A-MR1", "msg": "adam.sandor is allowed to read movies/124442 because part of movie-readers group"}
    ],
    "applied_denies": [
      {"name": "D-MR2", "msg": "adam.sandor is not allowed to read movies/124442"}
    ],
    "resolution_strategy": "default-deny",
    "overrule": true
  }
}
```

## Future functionality

### Output Adapters
To make Rune rule sets work with enforcement points like the Kubernetes API server or Envoy the outputs have to be
modified to fit the expected format. These adapters can be provided as part of the framework + an extension point in
user code.

### Rune Bundle
Easy way to bundle a specific version of Rune with user code. Opens the opportunity of pre-processing, for example
to create a json file with a list of packages containing rule sets.

```bash
rune --version=0.1.1 bundle ./
```

### Custom Resolution Strategies