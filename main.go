package main

import (
	"os"

	"mleku.net/noshtr/app"
	"mleku.net/slog"
)

var log, chk = slog.New(os.Stderr)

func main() {
	log.I.F("%s - %s", app.Name, app.Description)

}
