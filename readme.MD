# .env
AWS_REGION=sa-east-1
COGNITO_USER_POOL_ID=sa-east-1_abyVMc2Px
S3_BUCKET=your-bucket-name

DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=userdb
DB_SSLMODE=disable

PORT=8080

# ============================================================================
# go.mod
# ============================================================================
module backend

go 1.21

require (
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/aws/aws-sdk-go-v2/config v1.26.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.47.5
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/google/uuid v1.5.0
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.5.1
	github.com/lib/pq v1.10.9
)

# ============================================================================
# Инструкции по установке и запуску
# ============================================================================

# 1. Инициализация проекта
# Создайте папку проекта и откройте в VSCode
mkdir backend
cd backend

# 2. Инициализация Go модуля
go mod init backend

# 3. Создайте файл main.go с кодом из артефакта

# 4. Установка зависимостей
go get github.com/aws/aws-sdk-go-v2
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/golang-jwt/jwt/v5
go get github.com/google/uuid
go get github.com/gorilla/mux
go get github.com/joho/godotenv
go get github.com/lib/pq

# 5. Создайте файл .env с вашими настройками

# 6. Настройка PostgreSQL на Windows
# Скачайте PostgreSQL с https://www.postgresql.org/download/windows/
# Установите и создайте базу данных:

# Откройте psql:
psql -U postgres

# В psql выполните:
CREATE DATABASE userdb;

# 7. Настройка AWS S3 bucket
# В AWS Console создайте S3 bucket
# Настройте CORS для bucket:
# [
#   {
#     "AllowedHeaders": ["*"],
#     "AllowedMethods": ["GET", "PUT", "POST"],
#     "AllowedOrigins": ["https://localhost:44407"],
#     "ExposeHeaders": []
#   }
# ]

# Настройте публичный доступ (или используйте CloudFront)

# 8. Настройка AWS credentials
# Создайте файл C:\Users\YourUsername\.aws\credentials
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY

# 9. Запуск сервера
go run main.go

# ============================================================================
# Структура проекта
# ============================================================================
backend/
├── main.go           # Основной файл с всем кодом
├── .env              # Переменные окружения
├── go.mod            # Go модуль
└── go.sum            # Зависимости (создается автоматически)

# ============================================================================
# API Endpoints
# ============================================================================

# GET /api/profile
# Получение профиля текущего пользователя
# Headers: Authorization: Bearer <JWT_TOKEN>
# Response: { "sub": "...", "name": "...", "bio": "...", "photo_url": "...", ... }

# PUT /api/profile
# Обновление имени и биографии
# Headers: Authorization: Bearer <JWT_TOKEN>
# Body: { "name": "John Doe", "bio": "My bio" }
# Response: { "sub": "...", "name": "John Doe", "bio": "My bio", ... }

# POST /api/profile/photo
# Загрузка фотографии профиля
# Headers: Authorization: Bearer <JWT_TOKEN>
# Body: multipart/form-data with "photo" field
# Response: { "sub": "...", "photo_url": "https://...", ... }

# ============================================================================
# Пример использования с React
# ============================================================================

// api.ts
const API_BASE = 'http://localhost:8080';

async function getProfile(token: string) {
  const response = await fetch(`${API_BASE}/api/profile`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  return response.json();
}

async function updateProfile(token: string, name: string, bio: string) {
  const response = await fetch(`${API_BASE}/api/profile`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ name, bio })
  });
  return response.json();
}

async function uploadPhoto(token: string, file: File) {
  const formData = new FormData();
  formData.append('photo', file);

  const response = await fetch(`${API_BASE}/api/profile/photo`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: formData
  });
  return response.json();
}
# 1. GET /api/profile - Получение профиля
# ============================================================================

curl -X GET "http://localhost:8080/api/profile" ^
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# ============================================================================
# 2. PUT /api/profile - Обновление профиля (Windows CMD)
# ============================================================================

curl -X PUT "http://localhost:8080/api/profile" ^
  -H "Authorization: Bearer YOUR_JWT_TOKEN" ^
  -H "Content-Type: application/json" ^
  -d "{\"name\":\"Pablo\",\"bio\":\"Software developer\"}"

# ============================================================================
# 3. PUT /api/profile - Обновление профиля (PowerShell)
# ============================================================================

# В PowerShell используйте одинарные кавычки снаружи:
curl -X PUT "http://localhost:8080/api/profile" `
  -H "Authorization: Bearer YOUR_JWT_TOKEN" `
  -H "Content-Type: application/json" `
  -d '{\"name\":\"Pablo\",\"bio\":\"Software developer\"}'

# ============================================================================
# 4. POST /api/profile/photo - Загрузка фото
# ============================================================================

curl -X POST "http://localhost:8080/api/profile/photo" ^
  -H "Authorization: Bearer YOUR_JWT_TOKEN" ^
  -F "photo=@C:\path\to\your\photo.jpg"
