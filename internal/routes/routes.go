package routes

import (
	"net/http"

	"github.com/GiorgiUbiria/banking_system/internal/handlers"
	appmw "github.com/GiorgiUbiria/banking_system/internal/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRoutes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Works Fine!"))
	})

	r.Post("/auth/login", handlers.LoginHandler)

	r.With(appmw.Authenticated).Get("/accounts", handlers.GetAccountsHandler)

	r.Get("/accounts/{id}/balance", func(w http.ResponseWriter, r *http.Request) {
		idPram := chi.URLParam(r, "id")
		w.Write([]byte("Account balance! " + idPram))
	})

	r.Get("/transactions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Account balance!"))
	})

	return r
}
