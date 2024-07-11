package main

import (
	"os"

	"github.com/mleku/btcec/lol"
	"github.com/mleku/noshtr/app"
)

var log, chk, errorf = lol.New(os.Stderr)

func main() {
	log.I.F("%s - %s", app.Name, app.Description)

}
