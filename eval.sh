cp framework/rune.rego example/bundle
opa eval data.rune.results --bundle ./example/bundle -i example/input.json -f pretty