package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	app, err := New(Config{
		AdditionalTTL:          216000, // 1 hour
		ChainPrefix:            "KVAS2_",
		IpSetPrefix:            "kvas2_",
		LinkName:               "br0",
		TargetDNSServerAddress: "127.0.0.1",
		TargetDNSServerPort:    53,
		ListenDNSPort:          3553,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize application")
	}

	ctx, cancel := context.WithCancel(context.Background())

	log.Info().Msg("starting service")

	/*
		Starting app with graceful shutdown
	*/
	appResult := make(chan error)
	go func() {
		appResult <- app.Start(ctx)
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case err, _ := <-appResult:
			if err != nil {
				log.Error().Err(err).Msg("failed to start application")
			}
			log.Info().Msg("exiting application")
			return
		case <-c:
			log.Info().Msg("shutting down service")
			cancel()
		}
	}
}
