# Dockerfile для Go backend (multistage) — оптимизирован для деплоя на AWS ECS
# Использование distroless для минимального runtime-образа
# ARG позволяет менять версию Go при сборке образа
ARG GO_VERSION=1.21 
FROM golang:${GO_VERSION}-alpine AS builder
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Копируем манифесты зависимостей и кешируем их скачивание
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходники и собираем статически сжатый бинарник в папке контейнера /app
COPY . .

# CGO_ENABLED=0 для статической компиляции, отключаем от зависимостей C-библиотек
# -ldflags="-s -w" уменьшает размер бинарника (удаляет debug info и symbol table)
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /server ./...

# Финальный образ — минимальный runtime
# Используем base вместо static, чтобы иметь libc (если понадобится)
FROM gcr.io/distroless/static-debian11

# Копируем CA сертификаты из builder'а (критично для HTTPS запросов к AWS)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Копируем информацию о часовых поясах (опционально, но полезно для логов)
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Копируем бинарник из builder'а во второй стэйдж
COPY --from=builder /server /server
ENV APP_PORT=8080
EXPOSE 8080

# Запуск сервиса
ENTRYPOINT ["/server"]
