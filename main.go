// main.go
package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"github.com/aws/aws-xray-sdk-go/xray"

	_ "github.com/lib/pq" // <-- ВАЖНО: регистрируем драйвер postgres
)

func main() {
	// Загрузка переменных окружения
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, значения будут браться из окружения")
	}

	// Инициализация БД
	db, err := InitDB()
	if err != nil {
		log.Fatalf("Failed to initialize database %q: %v", os.Getenv("DB_NAME"), err)
	}
	defer db.Close() // по завершению функции выполнится

	// Инициализация S3
	s3Client := InitS3()

	// Инициализация JWT валидатора
	jwtValidator, err := NewCognitoJWTValidator(
		os.Getenv("AWS_REGION"),
		os.Getenv("COGNITO_USER_POOL_ID"),
	)
	if err != nil {
		log.Fatal("Failed to initialize JWT validator:", err)
	}

	// Создание и запуск сервера
	server := NewServer(db, s3Client, jwtValidator)

	log.Printf("Region -  %s", os.Getenv("AWS_REGION"))
	// log.Printf("PORT (default)-  %s", os.Getenv("PORT"))
	dir, _ := os.Getwd()
	log.Println("WORKDIR:", dir)

	port := os.Getenv("APP_PORT")
	log.Printf("APP_PORT -  %s", os.Getenv("APP_PORT"))
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := server.Start(":" + port); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// ============================================================================
// jwt_validator.go - Полная валидация JWT от AWS Cognito
// ============================================================================

type CognitoJWK struct {
	Keys []struct {
		Alg string `json:"alg"`
		E   string `json:"e"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		Use string `json:"use"`
	} `json:"keys"`
}

type CognitoJWTValidator struct {
	region     string
	userPoolID string
	jwkURL     string
	keySet     map[string]*rsa.PublicKey
	mu         sync.RWMutex
	lastFetch  time.Time
}

type CognitoClaims struct {
	jwt.RegisteredClaims
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	TokenUse      string `json:"token_use"`
	ClientID      string `json:"client_id"`
}

func NewCognitoJWTValidator(region, userPoolID string) (*CognitoJWTValidator, error) {
	if region == "" || userPoolID == "" {
		return nil, errors.New("region  and userPoolID are required")
	}

	validator := &CognitoJWTValidator{
		region:     region,
		userPoolID: userPoolID,
		jwkURL:     fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID),
		keySet:     make(map[string]*rsa.PublicKey),
	}

	// Предзагрузка ключей
	if err := validator.fetchJWKs(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs: %w", err)
	}

	return validator, nil
}

func (v *CognitoJWTValidator) fetchJWKs() error {
	resp, err := http.Get(v.jwkURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var jwks CognitoJWK
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKs: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}

		v.keySet[key.Kid] = pubKey
	}

	v.lastFetch = time.Now()
	return nil
}

func (v *CognitoJWTValidator) getPublicKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, exists := v.keySet[kid]
	shouldRefresh := time.Since(v.lastFetch) > 24*time.Hour
	v.mu.RUnlock()

	if !exists || shouldRefresh {
		if err := v.fetchJWKs(); err != nil {
			return nil, err
		}

		v.mu.RLock()
		key, exists = v.keySet[kid]
		v.mu.RUnlock()

		if !exists {
			return nil, errors.New("key not found in JWK set")
		}
	}

	return key, nil
}

func (v *CognitoJWTValidator) ValidateToken(tokenString string) (*CognitoClaims, error) {
	// Удаление префикса Bearer если есть
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	// Парсинг без валидации для получения kid
	token, err := jwt.ParseWithClaims(tokenString, &CognitoClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Получение kid из заголовка
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid not found in token header")
		}

		// Получение публичного ключа
		return v.getPublicKey(kid)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*CognitoClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	// Валидация issuer
	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", v.region, v.userPoolID)
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, claims.Issuer)
	}

	// Валидация token_use
	if claims.TokenUse != "access" && claims.TokenUse != "id" {
		return nil, fmt.Errorf("invalid token_use: %s", claims.TokenUse)
	}

	// Валидация времени
	now := time.Now()
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(now) {
		return nil, errors.New("token expired")
	}

	if claims.NotBefore != nil && claims.NotBefore.After(now) {
		return nil, errors.New("token not yet valid")
	}

	return claims, nil
}

// ============================================================================
// database.go - PostgreSQL
// ============================================================================

type User struct {
	Sub       string    `json:"sub"`
	Name      string    `json:"name"`
	Bio       string    `json:"bio"`
	PhotoURL  string    `json:"photo_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func InitDB() (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Создание таблицы если не существует
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		sub VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL DEFAULT '',
		bio TEXT NOT NULL DEFAULT '',
		photo_url TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMP NOT NULL DEFAULT NOW()
	);
	
	CREATE INDEX IF NOT EXISTS idx_users_sub ON users(sub);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		return nil, err
	}

	return db, nil
}

func GetOrCreateUser(db *sql.DB, sub string) (*User, error) {
	user := &User{}
	err := db.QueryRow(`
		INSERT INTO users (sub, name, bio, photo_url)
		VALUES ($1, '', '', '')
		ON CONFLICT (sub) DO UPDATE SET updated_at = NOW()
		RETURNING sub, name, bio, photo_url, created_at, updated_at
	`, sub).Scan(&user.Sub, &user.Name, &user.Bio, &user.PhotoURL, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func UpdateUserProfile(db *sql.DB, sub, name, bio string) error {
	_, err := db.Exec(`
		UPDATE users 
		SET name = $1, bio = $2, updated_at = NOW()
		WHERE sub = $3
	`, name, bio, sub)
	return err
}

func UpdateUserPhoto(db *sql.DB, sub, photoURL string) error {
	_, err := db.Exec(`
		UPDATE users 
		SET photo_url = $1, updated_at = NOW()
		WHERE sub = $2
	`, photoURL, sub)
	return err
}

// ============================================================================
// s3.go - AWS S3 для загрузки фото
// ============================================================================

type S3Client struct {
	client *s3.Client
	bucket string
}

func InitS3() *S3Client {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(os.Getenv("AWS_REGION")),
	)
	if err != nil {
		log.Fatal("Failed to load AWS config:", err)
	}

	return &S3Client{
		client: s3.NewFromConfig(cfg),
		bucket: os.Getenv("S3_BUCKET"),
	}
}

// GeneratePresignedURL - генерация presigned URL для загрузки в S3
func (s *S3Client) GeneratePresignedURL(ctx context.Context, userSub, fileName, contentType string) (*PresignedURLResponse, error) {
	// Валидация типа файла
	if !strings.HasPrefix(contentType, "image/") {
		return nil, fmt.Errorf("content type must be an image, got: %s", contentType)
	}

	// Разрешённые форматы
	allowedTypes := map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/gif":  true,
		"image/webp": true,
	}

	if !allowedTypes[contentType] {
		return nil, fmt.Errorf("unsupported image type: %s", contentType)
	}

	// Генерация уникального имени файла
	ext := filepath.Ext(fileName)
	if ext == "" {
		// Определяем расширение по MIME-типу если не указано
		switch contentType {
		case "image/jpeg", "image/jpg":
			ext = ".jpg"
		case "image/png":
			ext = ".png"
		case "image/gif":
			ext = ".gif"
		case "image/webp":
			ext = ".webp"
		}
	}

	// Формируем путь: profiles/{user_sub}/{uuid}{extension}
	s3Key := fmt.Sprintf("profiles/%s/%s%s", userSub, uuid.New().String(), ext)

	// Создаём presigned URL для PUT запроса
	presignClient := s3.NewPresignClient(s.client)

	// Параметры для presigned URL
	putObjectInput := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s3Key),
		ContentType: aws.String(contentType),
		// Добавляем метаданные для дополнительной безопасности
		// Metadata: map[string]string{
		// 	"user-sub":    userSub,
		// 	"uploaded-at": time.Now().Format(time.RFC3339),
		// },
	}

	// Генерируем presigned URL (действителен 15 минут)
	presignedReq, err := presignClient.PresignPutObject(ctx, putObjectInput,
		s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	// Формируем финальный URL файла
	photoURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
		s.bucket,
		os.Getenv("AWS_REGION"),
		s3Key,
	)

	log.Printf("[PRESIGNED] Generated URL for user: %s, file: %s", userSub, fileName)
	log.Printf("Photo URL %s", photoURL)
	//log.Printf("BucketL %s", s.bucket)

	return &PresignedURLResponse{
		UploadURL: presignedReq.URL,
		PhotoURL:  photoURL,
		ExpiresIn: 900, // 15 минут в секундах
	}, nil
}

// DeleteObjectByURL removes the previous photo from S3 once a new one is confirmed.
func (s *S3Client) DeleteObjectByURL(ctx context.Context, photoURL string) error {
	if photoURL == "" {
		return errors.New("photo URL is empty")
	}

	expectedPrefix := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", s.bucket, os.Getenv("AWS_REGION"))
	if !strings.HasPrefix(photoURL, expectedPrefix) {
		return fmt.Errorf("photo URL does not belong to managed bucket")
	}

	objectKey := strings.TrimPrefix(photoURL, expectedPrefix)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("failed to delete old photo: %w", err)
	}

	return nil
}

// ============================================================================
// server.go - HTTP сервер с API
// ============================================================================

// PresignedURLRequest - запрос на получение presigned URL
type PresignedURLRequest struct {
	FileName    string `json:"file_name"`
	ContentType string `json:"content_type"`
}

// PresignedURLResponse - ответ с presigned URL
type PresignedURLResponse struct {
	UploadURL string `json:"upload_url"` // URL для загрузки файла в S3
	PhotoURL  string `json:"photo_url"`  // Финальный URL загруженного файла
	ExpiresIn int    `json:"expires_in"` // Время жизни URL в секундах
}

// ConfirmUploadRequest - запрос на подтверждение загрузки
type ConfirmUploadRequest struct {
	PhotoURL string `json:"photo_url"`
}

// / ------------------ end PresignedURLRequest
type Server struct {
	db        *sql.DB
	s3        *S3Client
	validator *CognitoJWTValidator
	router    *mux.Router
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type UpdateProfileRequest struct {
	Name string `json:"name"`
	Bio  string `json:"bio"`
}

func NewServer(db *sql.DB, s3 *S3Client, validator *CognitoJWTValidator) *Server {
	s := &Server{
		db:        db,
		s3:        s3,
		validator: validator,
		router:    mux.NewRouter(),
	}

	s.setupRoutes()
	return s
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) setupRoutes() {
	// API routes
	api := s.router.PathPrefix("/api").Subrouter()

	// CORS только для /api
	api.Use(s.corsMiddleware)

	// Auth только для /api
	api.Use(s.authMiddleware)

	api.HandleFunc("/profile", s.getProfile).Methods("GET", "OPTIONS")
	api.HandleFunc("/profile", s.updateProfile).Methods("POST", "OPTIONS")
	api.HandleFunc("/profile/presigned-url", s.getPresignedURL).Methods("POST", "OPTIONS")
	api.HandleFunc("/profile/confirm-upload", s.confirmPhotoUpload).Methods("POST", "OPTIONS")

}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.sendError(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		claims, err := s.validator.ValidateToken(authHeader)
		if err != nil {
			s.sendError(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Добавление claims в контекст
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := ctx.Value("claims").(*CognitoClaims)
	// ошибка игнорируется, т.к. обработка внутри функции
	_ = xray.Capture(ctx, "GetProfile", func(ctx context.Context) error {
		// индексируемая метка
		xray.AddAnnotation(ctx, "op", "get_profile")

		log.Println("GetProfile call in Capture(...)")

		var user *User
		err := xray.Capture(ctx, "DB:GetOrCreateUser", func(ctx context.Context) error {
			u, err := GetOrCreateUser(s.db, claims.Sub)
			if err != nil {
				return err
			}
			user = u
			return nil
		}) // end capture
		if err != nil {
			s.sendError(w, "Failed to get user profile", http.StatusInternalServerError)
			return nil
		}

		s.sendJSON(w, user, http.StatusOK)
		return nil
	}) // end capture
}
func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*CognitoClaims)
	log.Println("UpdateProfile call")

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Валидация
	if len(req.Name) > 255 {
		s.sendError(w, "Name too long (max 255 characters)", http.StatusBadRequest)
		return
	}

	if len(req.Bio) > 5000 {
		s.sendError(w, "Bio too long (max 5000 characters)", http.StatusBadRequest)
		return
	}

	if err := UpdateUserProfile(s.db, claims.Sub, req.Name, req.Bio); err != nil {
		s.sendError(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	user, _ := GetOrCreateUser(s.db, claims.Sub)
	s.sendJSON(w, user, http.StatusOK)
}

func (s *Server) sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) sendError(w http.ResponseWriter, message string, status int) {
	s.sendJSON(w, ErrorResponse{Error: message}, status)
}

func (s *Server) Start(addr string) error {
	//Health пробрасываем без X-Ray, остальное — через X-Ray обёртку
	root := http.NewServeMux()
	root.HandleFunc("/health", s.healthCheck)

	traced := xray.Handler(xray.NewFixedSegmentNamer("go-backend"), s.router)

	root.Handle("/api/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// те же заголовки, что в corsMiddleware
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
			return
		}

		traced.ServeHTTP(w, r)
	}))

	return http.ListenAndServe(addr, root)
}

// getPresignedURL - хендлер для получения presigned URL
func (s *Server) getPresignedURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := ctx.Value("claims").(*CognitoClaims)

	_ = xray.Capture(ctx, "GetPresignedURL", func(ctx context.Context) error {
		var req PresignedURLRequest
		log.Printf("- GetPresignedURL request (Captured)")
		xray.AddAnnotation(ctx, "op", "get_presigned_url")

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.sendError(w, "Invalid request body", http.StatusBadRequest)
			return nil
		}
		if req.FileName == "" || req.ContentType == "" {
			s.sendError(w, "file_name and content_type are required", http.StatusBadRequest)
			return nil
		}

		var resp *PresignedURLResponse // ответ с presigned URL
		// ошибка игнорируется, т.к. обработка внутри функции
		if err := xray.Capture(ctx, "S3:GeneratePresignedURL", func(ctx context.Context) error {
			r, err := s.s3.GeneratePresignedURL(ctx, claims.Sub, req.FileName, req.ContentType)
			if err != nil {
				return err
			}
			resp = r
			return nil
		}); err != nil {
			s.sendError(w, "Failed to generate presigned URL: "+err.Error(), http.StatusBadRequest)
			return nil
		}

		s.sendJSON(w, resp, http.StatusOK)
		return nil
	})
}

// confirmPhotoUpload - подтверждение успешной загрузки фото
func (s *Server) confirmPhotoUpload(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*CognitoClaims)
	log.Printf("[API] ConfirmPhotoUpload request from user: %s", claims.Sub)

	var req ConfirmUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode request: %v", err)
		s.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PhotoURL == "" {
		s.sendError(w, "photo_url is required", http.StatusBadRequest)
		return
	}

	expectedPrefix := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/profiles/%s/",
		s.s3.bucket,
		os.Getenv("AWS_REGION"),
		claims.Sub,
	)

	if !strings.HasPrefix(req.PhotoURL, expectedPrefix) {
		log.Printf("[ERROR] Invalid photo URL: %s, expected prefix: %s", req.PhotoURL, expectedPrefix)
		s.sendError(w, "Invalid photo URL", http.StatusBadRequest)
		return
	}

	currentUser, err := GetOrCreateUser(s.db, claims.Sub)
	if err != nil {
		log.Printf("[ERROR] Failed to load user before deleting old photo: %v", err)
		s.sendError(w, "Failed to load user profile", http.StatusInternalServerError)
		return
	}
	previousPhotoURL := currentUser.PhotoURL

	if err := UpdateUserPhoto(s.db, claims.Sub, req.PhotoURL); err != nil {
		log.Printf("[ERROR] Failed to update photo in DB: %v", err)
		s.sendError(w, "Failed to update photo URL", http.StatusInternalServerError)
		return
	}

	if previousPhotoURL != "" && previousPhotoURL != req.PhotoURL {
		go func(oldURL, userID string) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := s.s3.DeleteObjectByURL(ctx, oldURL); err != nil {
				log.Printf("[WARN] Failed to delete old photo for user %s: %v", userID, err)
				return
			}
			log.Printf("[INFO] Deleted old photo for user: %s", userID)
		}(previousPhotoURL, claims.Sub)
	}

	log.Printf("[SUCCESS] Photo URL updated for user: %s, URL: %s", claims.Sub, req.PhotoURL)

	user, err := GetOrCreateUser(s.db, claims.Sub)
	if err != nil {
		s.sendError(w, "Failed to load user profile", http.StatusInternalServerError)
		return
	}
	s.sendJSON(w, user, http.StatusOK)
}
