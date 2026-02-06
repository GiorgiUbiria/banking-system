package routes

import (
	"net/http"

	"github.com/GiorgiUbiria/banking_system/internal/handlers"
	appmw "github.com/GiorgiUbiria/banking_system/internal/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	httpSwagger "github.com/swaggo/http-swagger"
)

func NewRoutes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Works Fine!"))
	})

	r.Post("/auth/login", handlers.LoginHandler)
	r.With(appmw.Authenticated).Get("/auth/me", handlers.MeHandler)

	r.With(appmw.Authenticated).Get("/accounts", handlers.GetAccountsHandler)

	r.With(appmw.Authenticated).Get("/accounts/{id}/balance", handlers.AccountBalanceHandler)

	r.With(appmw.Authenticated).Get("/transactions", handlers.TransactionsHandler)

	r.With(appmw.Authenticated).Post("/transactions/transfer", handlers.TransferHandler)

	r.With(appmw.Authenticated).Post("/transactions/exchange", handlers.ExchangeHandler)

	r.With(appmw.Authenticated).Get("/ledger", handlers.LedgerEntriesHandler)

	r.Get("/swagger/*", httpSwagger.WrapHandler)

	return r
}
