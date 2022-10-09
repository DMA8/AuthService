package grpc

import (
	"context"
	"log"
	"net"

	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/internal/domain/models"
	"github.com/DMA8/authService/internal/ports"
	"github.com/DMA8/authService/pkg/grpc_auth"
	"github.com/DMA8/authService/pkg/logging"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

var tracer trace.Tracer

type AuthServer struct {
	authService ports.Auth
	cfg         config.GRPCConfig
	logger      logging.Logger
	grpc_auth.UnimplementedAuthServer
}

func newTracerProvider() (*tracesdk.TracerProvider, error) {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint("http://jaeger-instance-collector.observability:14268/api/traces")),
	)
	if err != nil {
		return nil, err
	}

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exp),
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("team31_auth"),
		)))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	tracer = tp.Tracer("team31_auth")
	log.Println("tracer is set")
	return tp, nil
}

func NewAuthServer(cfg config.GRPCConfig, authService ports.Auth, l logging.Logger) *AuthServer {
	newTracerProvider()
	return &AuthServer{
		authService: authService,
		cfg:         cfg,
		logger:      l,
	}
}

func (a *AuthServer) Validate(ctx context.Context, credentials *grpc_auth.Credential) (*grpc_auth.ValidateResponse, error) {
	const (
		success    = true
		isUpdated  = true
		fail       = false
		notUpdated = false
	)

	ctx, span := tracer.Start(ctx, "auth grpc Validate")
	defer span.End()
	accessLogin, err := a.authService.ValidateToken(ctx, credentials.AccessToken)
	if err != nil {
		a.logger.Debug().Err(err).Msgf("auth.Validate couldn't validate access token! %+v", credentials)
		loginFromRefreshToken, err := a.authService.ValidateToken(ctx, credentials.RefreshToken)
		if err != nil {
			a.logger.Debug().Err(err).Msgf("auth.Validate couldn't validate refresh token! %+v", credentials)
			return createResponse("", "", "", fail, notUpdated), err
		}
		accessToken, err := a.authService.CreateToken(ctx, loginFromRefreshToken, models.AccessTokenType)
		if err != nil {
			a.logger.Debug().Err(err).Msgf("auth.Validate couldn't create access token! %+v", credentials)
			return createResponse("", "", "", fail, notUpdated), err
		}
		refreshToken, err := a.authService.CreateToken(ctx, loginFromRefreshToken, models.RefreshTokenType)
		if err != nil {
			a.logger.Debug().Err(err).Msgf("auth.Validate couldn't create refresh token! %+v", credentials)
			return createResponse("", "", "", fail, notUpdated), err
		}
		a.logger.Info().Err(err).Msgf("auth.Validate tokens are updated %+v", credentials)
		return createResponse(accessToken, refreshToken, loginFromRefreshToken, success, isUpdated), nil
	}
	a.logger.Info().Err(err).Msgf("auth.Validate accessToken is alive. no need to update %+v", credentials)
	return createResponse("", "", accessLogin, success, notUpdated), nil
}

func (a *AuthServer) LaunchGRPCServer() chan error {
	chanErr := make(chan error)
	lis, err := net.Listen(a.cfg.Transport, a.cfg.URI)
	if err != nil {
		chanErr <- err
		return chanErr
	}
	s := grpc.NewServer(
		grpc.UnaryInterceptor(otelgrpc.UnaryServerInterceptor()),
		grpc.StreamInterceptor(otelgrpc.StreamServerInterceptor()),
	)
	grpc_auth.RegisterAuthServer(s, a)
	go func() {
		chanErr <- s.Serve(lis)
	}()
	return chanErr
}

func createResponse(access, refresh, login string, success, isUpdate bool) *grpc_auth.ValidateResponse {
	return &grpc_auth.ValidateResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		Login:        login,
		Success:      success,
		IsUpdate:     isUpdate,
	}
}
