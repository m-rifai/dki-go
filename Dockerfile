# Build stage
FROM golang:1.19-alpine AS builder

# Set environment variables
ENV GO111MODULE=on
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Membuat folder logs
RUN mkdir -p logs

# Build the application
RUN go build -o main .

# Final stage: minimal image
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/logs /root/logs
EXPOSE 8080
CMD ["./main"]
