cp framework/rune_test.rego example/bundle
cp framework/rune.rego example/bundle
opa test --bundle ./example/bundle -f pretty -v