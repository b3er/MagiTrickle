GOOS=linux GOMIPS=softfloat GOARCH=mipsle go build -v -a -trimpath -ldflags="-w -s" .
