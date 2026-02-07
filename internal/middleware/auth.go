package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/GiorgiUbiria/banking_system/configs"
	"github.com/GiorgiUbiria/banking_system/internal/httputil"
	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/golang-jwt/jwt/v5"
)

const UserIDContextKey = "userID"

func Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			httputil.WriteError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			httputil.WriteError(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}

		tokenStr := parts[1]

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrTokenSignatureInvalid
			}
			return []byte(configs.AppConfig.JWT.SECRET), nil
		})
		if err != nil || !token.Valid {
			httputil.WriteError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			httputil.WriteError(w, http.StatusUnauthorized, "invalid token claims")
			return
		}

		sub, ok := claims["sub"].(float64)
		if !ok {
			logger.Log.Error("jwt subject missing or wrong type")
			httputil.WriteError(w, http.StatusUnauthorized, "invalid token payload")
			return
		}

		userID := uint64(sub)

		ctx := context.WithValue(r.Context(), UserIDContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

