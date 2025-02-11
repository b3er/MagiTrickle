package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"kvas2-go/models"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfgFile, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to read config.yaml")
	}

	cfg := models.ConfigFile{}
	err = yaml.Unmarshal(cfgFile, &cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse config.yaml")
	}

	app, err := New(cfg)

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
