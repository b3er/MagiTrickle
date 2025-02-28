package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"magitrickle"
	"magitrickle/constant"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().
		Str("version", constant.Version).
		Str("commit", constant.Commit).
		Msg("starting MagiTrickle daemon")

	app := magitrickle.New()

	log.Info().Msg("starting service")

	/*
		Starting app with graceful shutdown
	*/
	ctx, cancel := context.WithCancel(context.Background())
	appResult := make(chan error)
	go func() {
		appResult <- app.Start(ctx)
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	var once sync.Once
	closeEvent := func() {
		log.Info().Msg("shutting down service")
		cancel()
	}

	for {
		select {
		case err, _ := <-appResult:
			if err != nil {
				log.Error().Err(err).Msg("failed to start application")
			}
			log.Info().Msg("exiting application")
			return
		case <-c:
			once.Do(closeEvent)
		}
	}
}
