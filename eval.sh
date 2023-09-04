if [ -z "$1" ]; then
    echo "Error: No argument provided." >&2
    exit 1
fi

cp framework/rune.rego example/bundle
opa eval data.rune.results --bundle ./example/bundle -i example/$1 -f pretty