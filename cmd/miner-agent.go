package main

import (
	"github.com/common-nighthawk/go-figure"

	"github.com/a4913994/miner/pkg/cmd"
)

func main() {
	intro := figure.NewColorFigure("Miner Agent ", "roman", "blue", true)
	intro.Print()

	command := cmd.NewDefaultMinerCommand()
	if err := command.Execute(); err != nil {
		panic(err)
	}
}
