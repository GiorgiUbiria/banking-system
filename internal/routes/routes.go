package routes

import (
	"net/http"

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

	r.Get("/auth/me", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Me!"))
	})

	r.Get("/accounts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Accounts!"))
	})

	r.Get("/accounts/{id}/balance", func(w http.ResponseWriter, r *http.Request) {
		idPram := chi.URLParam(r, "id")
		w.Write([]byte("Account balance! " + idPram))
	})

	r.Get("/transactions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Account balance!"))
	})

	return r
}
