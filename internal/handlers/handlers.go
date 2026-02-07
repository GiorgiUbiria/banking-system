package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/GiorgiUbiria/banking_system/configs"
	"github.com/GiorgiUbiria/banking_system/internal/httputil"
	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/GiorgiUbiria/banking_system/internal/models"
	"github.com/GiorgiUbiria/banking_system/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type TransferRequest struct {
	FromAccountID uint64 `json:"from_account_id"`
	ToAccountID   uint64 `json:"to_account_id"`
	Amount        string `json:"amount"`
}

type ExchangeRequest struct {
	FromAccountID uint64 `json:"from_account_id"`
	ToAccountID   uint64 `json:"to_account_id"`
	Amount        string `json:"amount"`
}

type TransferResponse struct {
	Message string `json:"message"`
}

type ExchangeResponse struct {
	Message string `json:"message"`
}

type TransactionsResponse struct {
	Transactions []models.Transaction `json:"transactions"`
}

type LedgerEntriesResponse struct {
	Entries []models.LedgerEntry `json:"entries"`
}

type MeResponse struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AccountBalanceResponse struct {
	ID       uint            `json:"id"`
	Currency string          `json:"currency"`
	Balance  decimal.Decimal `json:"balance"`
}

type ReconcileEntry struct {
	AccountID     uint            `json:"account_id"`
	Currency      string          `json:"currency"`
	StoredBalance decimal.Decimal `json:"stored_balance"`
	LedgerSum     decimal.Decimal `json:"ledger_sum"`
	Match         bool            `json:"match"`
}

type ReconcileResponse struct {
	Accounts []ReconcileEntry `json:"accounts"`
	AllMatch bool             `json:"all_match"`
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
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var accounts []models.Account
	if err := store.DB.
		Where("user_id = ?", userID).
		Find(&accounts).Error; err != nil {

		logger.Log.Error("failed to fetch accounts", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch accounts")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(accounts); err != nil {
		logger.Log.Error("failed to encode response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
}

// AccountBalanceHandler godoc
// @Summary      Get account balance
// @Description  Get balance for a specific account belonging to the authenticated user
// @Tags         accounts
// @Produce      json
// @Param        id   path      int  true  "Account ID"
// @Success      200  {object}  AccountBalanceResponse
// @Failure      400  {string}  string  "invalid account id"
// @Failure      401  {string}  string  "unauthorized"
// @Failure      403  {string}  string  "forbidden"
// @Failure      404  {string}  string  "account not found"
// @Failure      500  {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /accounts/{id}/balance [get]
func AccountBalanceHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		httputil.WriteError(w, http.StatusBadRequest, "invalid account id")
		return
	}

	var acc models.Account
	if err := store.DB.First(&acc, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "account not found")
			return
		}
		logger.Log.Error("failed to load account", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch account")
		return
	}

	if acc.UserID != userID {
		httputil.WriteError(w, http.StatusForbidden, "forbidden")
		return
	}

	resp := AccountBalanceResponse{
		ID:       acc.ID,
		Currency: acc.Currency,
		Balance:  acc.Balance,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Log.Error("failed to encode account balance response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
}

// ReconcileHandler godoc
// @Summary      Reconcile account balances with ledger
// @Description  Verify that each account's stored balance matches the sum of its ledger entries
// @Tags         accounts
// @Produce      json
// @Success      200  {object}  ReconcileResponse
// @Failure      401  {string}  string  "unauthorized"
// @Failure      500  {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /accounts/reconcile [get]
func ReconcileHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var accounts []models.Account
	if err := store.DB.Where("user_id = ?", userID).Find(&accounts).Error; err != nil {
		logger.Log.Error("failed to fetch accounts", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch accounts")
		return
	}

	entries := make([]ReconcileEntry, 0, len(accounts))
	allMatch := true

	for _, acc := range accounts {
		var row struct {
			Total decimal.Decimal
		}
		err := store.DB.Raw("SELECT COALESCE(SUM(amount), 0) AS total FROM ledger_entries WHERE account_id = ?", acc.ID).Scan(&row).Error
		if err != nil {
			logger.Log.Error("failed to sum ledger for account", zap.Uint("account_id", uint(acc.ID)), zap.Error(err))
			httputil.WriteError(w, http.StatusInternalServerError, "failed to reconcile")
			return
		}
		match := acc.Balance.Equal(row.Total)
		if !match {
			allMatch = false
		}
		entries = append(entries, ReconcileEntry{
			AccountID:     uint(acc.ID),
			Currency:      acc.Currency,
			StoredBalance: acc.Balance,
			LedgerSum:     row.Total,
			Match:         match,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ReconcileResponse{Accounts: entries, AllMatch: allMatch}); err != nil {
		logger.Log.Error("failed to encode reconcile response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
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
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.WriteError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	var user models.User
	if err := store.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		httputil.WriteError(w, http.StatusUnauthorized, "invalid email or password")
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
		httputil.WriteError(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(LoginResponse{Token: signed}); err != nil {
		logger.Log.Error("failed to encode login response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
}

// MeHandler godoc
// @Summary      Get current user
// @Description  Get profile of the authenticated user
// @Tags         auth
// @Produce      json
// @Success      200  {object}  MeResponse
// @Failure      401  {string}  string  "unauthorized"
// @Failure      404  {string}  string  "user not found"
// @Failure      500  {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /auth/me [get]
func MeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var user models.User
	if err := store.DB.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			httputil.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		logger.Log.Error("failed to load user", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	resp := MeResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Log.Error("failed to encode me response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
}

// TransferHandler godoc
// @Summary      Transfer money between accounts
// @Description  Transfer money between accounts for the authenticated user
// @Tags         transactions
// @Accept       json
// @Produce      json
// @Param        transfer  body      TransferRequest  true  "Transfer request"
// @Success      200          {object}  TransferResponse
// @Failure      400          {string}  string  "invalid request"
// @Failure      401          {string}  string  "unauthorized"
// @Failure      500          {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /transactions/transfer [post]
func TransferHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	amt, err := decimal.NewFromString(req.Amount)
	if err != nil || !amt.IsPositive() {
		httputil.WriteError(w, http.StatusBadRequest, "amount must be a positive decimal")
		return
	}

	var (
		errInsufficientFunds = errors.New("insufficient funds")
		errForbiddenAccount  = errors.New("from account does not belong to user")
		errCurrencyMismatch  = errors.New("accounts must have same currency")
	)

	txErr := store.DB.Transaction(func(tx *gorm.DB) error {
		var fromAcc, toAcc models.Account
		id1, id2 := req.FromAccountID, req.ToAccountID
		if id1 > id2 {
			id1, id2 = id2, id1
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fromAcc, id1).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			return err
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&toAcc, id2).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			return err
		}
		if id1 != req.FromAccountID {
			fromAcc, toAcc = toAcc, fromAcc
		}

		if fromAcc.UserID != userID {
			return errForbiddenAccount
		}
		if fromAcc.Currency != toAcc.Currency {
			return errCurrencyMismatch
		}
		if fromAcc.Balance.LessThan(amt) {
			return errInsufficientFunds
		}

		tr := models.Transaction{
			UserID:   userID,
			Type:     "transfer",
			Status:   "pending",
			Currency: fromAcc.Currency,
		}
		if err := tx.Create(&tr).Error; err != nil {
			return err
		}

		fromAcc.Balance = fromAcc.Balance.Sub(amt)
		toAcc.Balance = toAcc.Balance.Add(amt)

		if err := tx.Save(&fromAcc).Error; err != nil {
			return err
		}
		if err := tx.Save(&toAcc).Error; err != nil {
			return err
		}

		entries := []models.LedgerEntry{
			{
				TxID:      uint64(tr.ID),
				AccountID: uint64(fromAcc.ID),
				Currency:  fromAcc.Currency,
				Amount:    amt.Neg(),
			},
			{
				TxID:      uint64(tr.ID),
				AccountID: uint64(toAcc.ID),
				Currency:  toAcc.Currency,
				Amount:    amt,
			},
		}
		if err := tx.Create(&entries).Error; err != nil {
			return err
		}

		tr.Status = "completed"
		if err := tx.Save(&tr).Error; err != nil {
			return err
		}

		return nil
	})
	if txErr != nil {
		switch {
		case errors.Is(txErr, errInsufficientFunds):
			httputil.WriteError(w, http.StatusBadRequest, "insufficient funds")
			return
		case errors.Is(txErr, errForbiddenAccount):
			httputil.WriteError(w, http.StatusForbidden, "cannot transfer from another user's account")
			return
		case errors.Is(txErr, errCurrencyMismatch):
			httputil.WriteError(w, http.StatusBadRequest, "accounts must have same currency")
			return
		case errors.Is(txErr, gorm.ErrRecordNotFound):
			httputil.WriteError(w, http.StatusNotFound, "account not found")
			return
		default:
			logger.Log.Error("transfer failed", zap.Error(txErr))
			httputil.WriteError(w, http.StatusInternalServerError, "failed to process transfer")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TransferResponse{
		Message: "transfer completed",
	})
}

// ExchangeHandler godoc
// @Summary      Exchange currency
// @Description  Exchange currency between user's own accounts (USD ↔ EUR) using fixed rate
// @Tags         transactions
// @Accept       json
// @Produce      json
// @Param        exchange  body      ExchangeRequest  true  "Exchange request"
// @Success      200       {object}  ExchangeResponse
// @Failure      400       {string}  string  "invalid request"
// @Failure      401       {string}  string  "unauthorized"
// @Failure      403       {string}  string  "forbidden"
// @Failure      404       {string}  string  "account not found"
// @Failure      500       {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /transactions/exchange [post]
func ExchangeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req ExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	amt, err := decimal.NewFromString(req.Amount)
	if err != nil || !amt.IsPositive() {
		httputil.WriteError(w, http.StatusBadRequest, "amount must be a positive decimal")
		return
	}

	var (
		errInsufficientFunds    = errors.New("insufficient funds")
		errForbiddenFromAccount = errors.New("from account does not belong to user")
		errForbiddenToAccount   = errors.New("to account does not belong to user")
		errSameCurrency         = errors.New("accounts must have different currencies")
	)

	rate := decimal.NewFromFloat(configs.AppConfig.ExchangeRate.UsdToEur)

	txErr := store.DB.Transaction(func(tx *gorm.DB) error {
		var fromAcc, toAcc models.Account
		id1, id2 := req.FromAccountID, req.ToAccountID
		if id1 > id2 {
			id1, id2 = id2, id1
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&fromAcc, id1).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			return err
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&toAcc, id2).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			return err
		}
		if id1 != req.FromAccountID {
			fromAcc, toAcc = toAcc, fromAcc
		}

		if fromAcc.UserID != userID {
			return errForbiddenFromAccount
		}
		if toAcc.UserID != userID {
			return errForbiddenToAccount
		}
		if fromAcc.Currency == toAcc.Currency {
			return errSameCurrency
		}
		if fromAcc.Balance.LessThan(amt) {
			return errInsufficientFunds
		}

		tr := models.Transaction{
			UserID:   userID,
			Type:     "exchange",
			Status:   "pending",
			Currency: fromAcc.Currency,
		}
		if err := tx.Create(&tr).Error; err != nil {
			return err
		}

		var amtToAdd decimal.Decimal
		switch fromAcc.Currency {
		case "USD":
			fromAcc.Balance = fromAcc.Balance.Sub(amt)
			amtToAdd = amt.Mul(rate)
			toAcc.Balance = toAcc.Balance.Add(amtToAdd)
		case "EUR":
			fromAcc.Balance = fromAcc.Balance.Sub(amt)
			amtToAdd = amt.Div(rate)
			toAcc.Balance = toAcc.Balance.Add(amtToAdd)
		}

		if err := tx.Save(&fromAcc).Error; err != nil {
			return err
		}
		if err := tx.Save(&toAcc).Error; err != nil {
			return err
		}

		entries := []models.LedgerEntry{
			{
				TxID:      uint64(tr.ID),
				AccountID: uint64(fromAcc.ID),
				Currency:  fromAcc.Currency,
				Amount:    amt.Neg(),
			},
			{
				TxID:      uint64(tr.ID),
				AccountID: uint64(toAcc.ID),
				Currency:  toAcc.Currency,
				Amount:    amtToAdd,
			},
		}
		if err := tx.Create(&entries).Error; err != nil {
			return err
		}

		tr.Status = "completed"
		if err := tx.Save(&tr).Error; err != nil {
			return err
		}

		return nil
	})
	if txErr != nil {
		switch {
		case errors.Is(txErr, errInsufficientFunds):
			httputil.WriteError(w, http.StatusBadRequest, "insufficient funds")
			return
		case errors.Is(txErr, errForbiddenFromAccount):
			httputil.WriteError(w, http.StatusForbidden, "cannot exchange from another user's account")
			return
		case errors.Is(txErr, errForbiddenToAccount):
			httputil.WriteError(w, http.StatusForbidden, "cannot exchange to another user's account")
			return
		case errors.Is(txErr, errSameCurrency):
			httputil.WriteError(w, http.StatusBadRequest, "accounts must have different currencies")
			return
		case errors.Is(txErr, gorm.ErrRecordNotFound):
			httputil.WriteError(w, http.StatusNotFound, "account not found")
			return
		default:
			logger.Log.Error("exchange failed", zap.Error(txErr))
			httputil.WriteError(w, http.StatusInternalServerError, "failed to process exchange")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExchangeResponse{
		Message: "exchange completed",
	})
}

// TransactionsHandler godoc
// @Summary      List user transactions
// @Description  Get all transactions for the authenticated user
// @Tags         transactions
// @Produce      json
// @Success      200  {array}   models.Transaction
// @Failure      401  {string}  string  "unauthorized"
// @Failure      500  {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /transactions [get]
func TransactionsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	q := r.URL.Query()
	typeFilter := q.Get("type")

	page := 1
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}

	limit := 20
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	offset := (page - 1) * limit

	var txs []models.Transaction
	db := store.DB.Where("user_id = ?", userID)
	if typeFilter != "" {
		db = db.Where("type = ?", typeFilter)
	}

	if err := db.
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&txs).Error; err != nil {

		logger.Log.Error("failed to fetch transactions", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch transactions")
		return
	}

	resp := TransactionsResponse{Transactions: txs}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Log.Error("failed to encode transactions response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
}

// LedgerEntriesHandler godoc
// @Summary      List user ledger entries
// @Description  Get ledger entries for the authenticated user, optionally filtered by transaction or account
// @Tags         ledger
// @Produce      json
// @Param        tx_id       query     int     false  "Transaction ID"
// @Param        account_id  query     int     false  "Account ID"
// @Param        page        query     int     false  "Page number"
// @Param        limit       query     int     false  "Page size (max 100)"
// @Success      200         {array}   models.LedgerEntry
// @Failure      401         {string}  string  "unauthorized"
// @Failure      500         {string}  string  "server error"
// @Security     ApiKeyAuth
// @Router       /ledger [get]
func LedgerEntriesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := ctx.Value("userID").(uint64)
	if !ok {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	q := r.URL.Query()
	txIDStr := q.Get("tx_id")
	accountIDStr := q.Get("account_id")

	page := 1
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}

	limit := 20
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	offset := (page - 1) * limit

	db := store.DB.Model(&models.LedgerEntry{})

	if accountIDStr != "" {
		accID, err := strconv.Atoi(accountIDStr)
		if err != nil || accID <= 0 {
			httputil.WriteError(w, http.StatusBadRequest, "invalid account_id")
			return
		}

		var acc models.Account
		if err := store.DB.First(&acc, accID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				httputil.WriteError(w, http.StatusNotFound, "account not found")
				return
			}
			logger.Log.Error("failed to load account", zap.Error(err))
			httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch ledger entries")
			return
		}
		if acc.UserID != userID {
			httputil.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}

		db = db.Where("account_id = ?", accID)
	} else if txIDStr != "" {
		tid, err := strconv.Atoi(txIDStr)
		if err != nil || tid <= 0 {
			httputil.WriteError(w, http.StatusBadRequest, "invalid tx_id")
			return
		}

		var tr models.Transaction
		if err := store.DB.First(&tr, tid).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				httputil.WriteError(w, http.StatusNotFound, "transaction not found")
				return
			}
			logger.Log.Error("failed to load transaction", zap.Error(err))
			httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch ledger entries")
			return
		}
		if tr.UserID != userID {
			httputil.WriteError(w, http.StatusForbidden, "forbidden")
			return
		}

		db = db.Where("tx_id = ?", tid)
	} else {
		sub := store.DB.Model(&models.Account{}).
			Select("id").
			Where("user_id = ?", userID)
		db = db.Where("account_id IN (?)", sub)
	}

	var entries []models.LedgerEntry
	if err := db.
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&entries).Error; err != nil {

		logger.Log.Error("failed to fetch ledger entries", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to fetch ledger entries")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		logger.Log.Error("failed to encode ledger entries response", zap.Error(err))
		httputil.WriteError(w, http.StatusInternalServerError, "failed to encode response")
		return
	}
}
