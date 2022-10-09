package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	grpc "github.com/DMA8/authService/internal/adapters/grpc"
	entrypoint "github.com/DMA8/authService/internal/adapters/http"
	repository "github.com/DMA8/authService/internal/adapters/mongodb"
	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/auth"
	"github.com/DMA8/authService/pkg/logging"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.NewConfig()
	logger := logging.New(cfg.Log.Level)
	logger.Info().Msgf("config\n %+v", cfg)

	repo, err := repository.NewRepository(ctx, cfg.Mongo)
	if err != nil {
		logger.Fatal().Err(err).Msg("repo init fail")
	}
	authService := auth.NewAuth(cfg.JWT, repo, logger)
	handler := entrypoint.NewHandler(cfg.HTTP, authService, logger)
	server := entrypoint.NewHTTPServer(cfg.HTTP, handler)
	grpcAuth := grpc.NewAuthServer(cfg.GRPC, authService, logger)

	errGRPCServ := grpcAuth.LaunchGRPCServer()
	errHTTPServ := entrypoint.StartHTTPServer(server)

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	logger.Info().Msg("auth ready")

	select {
	case err := <-errGRPCServ:
		logger.Error().Err(err).Msg("grpcServProblem")
	case err := <-errHTTPServ:
		logger.Error().Err(err).Msg("httpServ problems")
	case <-osSignals:
		logger.Info().Msg("shutdown the application")
		err := server.Shutdown(ctx)
		if err != nil {
			logger.Error().Err(err).Msg("couldn't shut down httpServ")
		}
	}
	cancel()
}
