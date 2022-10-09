package http

import (
	_ "github.com/DMA8/authService/docs"
	"net/http"
	"sync"

	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/DMA8/authService/internal/config"
	"github.com/DMA8/authService/pkg/logging"
	"github.com/DMA8/authService/internal/ports"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type Handler struct {
	mu          sync.Mutex
	auth        ports.Auth
	logger      logging.Logger
	cfg         config.HTTPConfig
	ProfEnabled bool
}

func NewHandler(config config.HTTPConfig, auth ports.Auth, logger logging.Logger) *Handler {
	return &Handler{
		logger: logger,
		auth:   auth,
		cfg:    config,
	}
}

func NewHTTPServer(cfg config.HTTPConfig, handler *Handler) *http.Server {
	r := initRouter(cfg, handler)
	return &http.Server{
		Handler: r,
		Addr:    cfg.URI,
	}
}

func StartHTTPServer(server *http.Server) chan error {
	chanErr := make(chan error)
	go func() {
		chanErr <- server.ListenAndServe()
	}()
	return chanErr
}

func initRouter(cfg config.HTTPConfig, handler *Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(Logger(handler.logger))
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:3000/swagger/doc.json")))
	r.Group(func(r chi.Router) {
		r.Use(handler.checkToken)
		r.Get(cfg.APIVersion+"/i", handler.I)
		r.Get(cfg.APIVersion+"/validate", handler.I)
		r.Get(cfg.APIVersion+"/profswitch", handler.Profiling)
	})
	r.Group(func(r chi.Router) {
		r.Use(handler.profilingCheck)
		r.Mount(cfg.APIVersion+"/prof/", middleware.Profiler())
	})
	r.Post(cfg.APIVersion+"/login", handler.Login)
	r.Get(cfg.APIVersion+"/logout", handler.Logout)
	r.Group(func(r chi.Router) {
		r.Use(handler.validateInput)
		r.Post(cfg.APIVersion+"/user", handler.CreateUser)
		r.Put(cfg.APIVersion+"/user", handler.UpdateUser)
	})
	r.Delete(cfg.APIVersion+"/user/{login}", handler.DeleteUser)
	r.Get(cfg.APIVersion+"/user/{login}", handler.GetUser)
	return r
}
