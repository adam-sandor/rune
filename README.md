# ᛤ Rune Framework for Rego ᛤ

An opinionated framework designed to help build maintainable and well-structured Rego code.
It acts as the entry point to all your rules and provides the following features:
* Translating rule results into well-structured output
* Output contains explanation of how it was calculated
* Mechanism for mixing allow and deny rules using strategies
* Grouping rules into rule sets that can be combined for a top-level result

## What are these opinions / best practices?

1. There should be a straight-forward way to group rules into larger sets and combine their results in a flexible way.
2. Combining rule outcomes should be based on well-defined configurable strategies rather than custom code.
3. Top level rules should be called `allow` and `deny` with results that can be combined intuitively.
4. Rule results should be easy to match to the rule that produced them.
5. Rule results should be objects to make them extensible.
6. Outputs should explain the final allow/deny result.

## Design guidelines for the framework

* Don't interfere with the user's ability to structure code into packages.
* Don't make the user do more work / write more code than without using the framework.
* Provide mechanism for custom outputs for compatibility with external enforcement points like Envoy or Kubernetes.

## Running a rules with Rune

### Rules

Here is a Rego rule in Rune format. The name of the rule (allow / deny) and it's result type (set of objects) 
is predefined. Each result object has a minimum of 2 properties (id and msg).
Your code is expected to be a series of such `allow` and `deny` rules one or more Rule Sets.

```rego
allow[result] {

    "movie-readers" in input.subject.groups
    regex.match("movies/\\d+", input.resource)
    input.action == "read"

    result := {
    	"id": "A-MR1",
        "msg": sprintf("%s is allowed to read %s because part of movie-readers group",
        	[input.subject.username, input.resource])
    }
}
```

### Rule sets

Rule Sets provide a clear way to structure your Rego code. They are Rego packages with some metadata and a rule
naming scheme.

```text
Note: Rune currently only supports Rule Sets that are sub-packages of the `policy` package.
```

Each Rule Set produces it's own allow or deny result. These can be combined into an overall result 
(see Rule result combining).

```text
bundle -> deny
\_ rule_set[policy.movies] -> allow 
\_ rule_set[policy.actors] -> deny
```

To provide the Rule Set's metadata Rune expects an object called `rule_set` to be defined in the package.
This provides configurable strategy for evaluating the sets of `allow` and `deny` results.
```rego
rule_set := {
	"name": "Access to Movies",
	"resolution_strategy": "default-deny"
}
```

## Rule result combination

The resolution strategy configuration in the Rule Set's metadata controls how the results of allow and deny rules combine
into a final result. Currently, Rune supports the following strategies:

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

## Execution

Rune provides the entrypoint rule, so it can take over the evaluation process. `rune.rego` must be packaged into
the bundle that get's deployed in OPA. Clients should invoke the `rune.results` rule:

Note: In this repo you can run the example movies/actors rule set using the `eval.sh` script and providing it with an
input file path (e.g. example/input-add-actor-to-movie.json). `eval.sh` will copy rune.rego into the example/bundle
folder

```shell
opa eval data.rune.results --bundle ./example/bundle -i example/input-add-actor-to-movie.json
```

The results from Rune look like this:
```json
{
  "resolution_strategy": "default-deny",
  "result": "allow",
  "rule_sets": {
    "actors": {
      "name": "Access to Actors",
      "reason": {
        "enforced_allows": [
          {
            "id": "A-ACT1",
            "msg": "adam.sandor can add and remove actors from movies"
          }
        ],
        "enforced_denies": [],
        "resolution_strategy": "default-deny"
      },
      "result": "allow",
      "result_validation_errors": []
    },
    "movies": {
      "name": "Access to Movies",
      "reason": {
        "enforced_allows": [
          {
            "id": "A-E-MR3",
            "msg": "adam.sandor is allowed to edit movies/224333 because part of movie-editors group"
          }
        ],
        "enforced_denies": [],
        "resolution_strategy": "default-deny-overrule"
      },
      "result": "allow",
      "result_validation_errors": []
    }
  }
}
```

## Sample rule bundle

The example folder contains a rule bundle that showcases Rune's functionality. There are two rule sets: actors and movies. 
These will combine into an overall rule result that will produce output similar to what's showin in the previous section.

Try running: `./eval.sh example/input-add-actor-to-movie.json` to see the results, and play around the input and the sample
rules!


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

Provide an extension point for users to define their own resolution strategies in the the form of a function.