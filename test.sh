cp framework/rune_tests.rego example/bundle
cp framework/rune.rego example/bundle
opa test --bundle ./example/bundle -f pretty -v