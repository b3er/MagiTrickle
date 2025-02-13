package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"kvas2"
	"kvas2/constant"
	"kvas2/models"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

const cfgFolderLocation = "/opt/var/lib/kvas2"
const cfgFileLocation = cfgFolderLocation + "/config.yaml"
const pidFileLocation = "/opt/var/run/kvas2.pid"

func checkPIDFile() error {
	data, err := os.ReadFile(pidFileLocation)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return errors.New("invalid PID file content")
	}

	if err := syscall.Kill(pid, 0); err == nil {
		return fmt.Errorf("process %d is already running", pid)
	}

	_ = os.Remove(pidFileLocation)
	return nil
}

func createPIDFile() error {
	pid := os.Getpid()
	return os.WriteFile(pidFileLocation, []byte(strconv.Itoa(pid)), 0644)
}

func removePIDFile() {
	_ = os.Remove(pidFileLocation)
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Info().
		Str("version", constant.Version).
		Str("commit", constant.Commit).
		Msg("starting kvas2 daemon")

	if err := checkPIDFile(); err != nil {
		log.Fatal().Err(err).Msg("failed to start kvas2 daemon")
	}

	if err := createPIDFile(); err != nil {
		log.Fatal().Err(err).Msg("failed to create PID file")
	}
	defer removePIDFile()

	cfg := models.ConfigFile{}

	cfgFile, err := os.ReadFile(cfgFileLocation)
	if err == nil {
		err = yaml.Unmarshal(cfgFile, &cfg)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to parse config.yaml")
		}

	} else {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Msg("failed to read config.yaml")
		}
		cfg = models.ConfigFile{
			AppConfig: models.AppConfig{
				LogLevel:               "info",
				AdditionalTTL:          216000,
				ChainPrefix:            "KVAS2_",
				IPSetPrefix:            "kvas2_",
				LinkName:               "br0",
				TargetDNSServerAddress: "127.0.0.1",
				TargetDNSServerPort:    53,
				ListenDNSPort:          3553,
			},
		}
		out, err := yaml.Marshal(cfg)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to serialize config.yaml")
		}
		err = os.MkdirAll(cfgFolderLocation, os.ModePerm)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to create config directory")
		}
		err = os.WriteFile(cfgFileLocation, out, 0600)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to save config.yaml")
		}
	}

	switch cfg.AppConfig.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "nolevel":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case "disabled":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	app, err := kvas2.New(cfg)
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
