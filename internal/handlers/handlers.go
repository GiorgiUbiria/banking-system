package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/GiorgiUbiria/banking_system/configs"
	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/GiorgiUbiria/banking_system/internal/models"
	"github.com/GiorgiUbiria/banking_system/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

// GetAccountsHandler godoc
// @Summary      List user accounts
// @Description  Get all accounts for the authenticated user
// @Tags         accounts
// @Produce      json
// @Success      200  {array}   models.Account
// @Failure      401  {string}  string  "unauthorized"
// @Failure      500  {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /accounts [get]
func GetAccountsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var accounts []models.Account
	if err := store.DB.
		Where("user_id = ?", userID).
		Find(&accounts).Error; err != nil {

		logger.Log.Error("failed to fetch accounts", zap.Error(err))
		http.Error(w, "failed to fetch accounts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(accounts); err != nil {
		logger.Log.Error("failed to encode response", zap.Error(err))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// LoginHandler godoc
// @Summary      User login
// @Description  Authenticate user and return JWT token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        credentials  body      LoginRequest  true  "Login credentials"
// @Success      200          {object}  LoginResponse
// @Failure      400          {string}  string  "invalid request"
// @Failure      401          {string}  string  "invalid email or password"
// @Router       /auth/login [post]
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}

	var user models.User
	if err := store.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}

	claims := jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(configs.AppConfig.JWT.SECRET))
	if err != nil {
		logger.Log.Error("failed to sign jwt", zap.Error(err))
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(LoginResponse{Token: signed}); err != nil {
		logger.Log.Error("failed to encode login response", zap.Error(err))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

