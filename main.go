package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "math"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"
    "time"

    "github.com/go-playground/validator/v10"
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
    "gorm.io/datatypes"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

type Stock struct {
    ID             uint           `json:"id" gorm:"primaryKey"`
    NamaBarang     string         `json:"nama_barang" validate:"required"`
    JumlahStok     int            `json:"jumlah_stok" validate:"gte=0"`
    NomorSeri      string         `json:"nomor_seri"`
    AdditionalInfo datatypes.JSON `json:"additional_info" gorm:"type:jsonb"`
    GambarBarang   string         `json:"gambar_barang"`
    CreatedAt      time.Time      `json:"created_at"`
    CreatedBy      string         `json:"created_by"`
    UpdatedAt      time.Time      `json:"updated_at"`
    UpdatedBy      string         `json:"updated_by"`
}

type Response struct {
    Status  string      `json:"status"`
    Message string      `json:"message,omitempty"`
    Data    interface{} `json:"data,omitempty"`
}

var (
    db            *gorm.DB
    logFileWriter *bufio.Writer
    validate      = validator.New()
    jwtKey        []byte
)

func init() {
    err := godotenv.Load()
    if err != nil {
        log.Println("No .env file found, using environment variables")
    }

    
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        log.Fatal("JWT_SECRET is not set")
    }
    jwtKey = []byte(secret)
}

func initDB() {
    var err error
    host := os.Getenv("POSTGRES_HOST")
    port := os.Getenv("POSTGRES_PORT")
    user := os.Getenv("POSTGRES_USER")
    password := os.Getenv("POSTGRES_PASSWORD")
    dbname := os.Getenv("POSTGRES_DB")

    if host == "" || port == "" || user == "" || password == "" || dbname == "" {
        log.Fatal("Database configuration is incomplete")
    }

    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
        host, user, password, dbname, port,
    )
    db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }

    err = db.AutoMigrate(&Stock{})
    if err != nil {
        log.Fatal("Failed to migrate database:", err)
    }

    log.Println("Connected to the database")
}

type ResponseRecorder struct {
    http.ResponseWriter
    StatusCode int
    Body       *bytes.Buffer
}

func (rr *ResponseRecorder) WriteHeader(statusCode int) {
    rr.StatusCode = statusCode
    rr.ResponseWriter.WriteHeader(statusCode)
}

func (rr *ResponseRecorder) Write(b []byte) (int, error) {
    if rr.Body.Len() < 1<<20 { 
        rr.Body.Write(b)
    }
    return rr.ResponseWriter.Write(b)
}

func LoggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        start := time.Now()
        requestBody, _ := logRequest(r)

        rr := &ResponseRecorder{ResponseWriter: w, Body: new(bytes.Buffer), StatusCode: http.StatusOK}
        next.ServeHTTP(rr, r)

        logResponse(r, rr, time.Since(start))

        logToFile("Request Body", r.Method, r.URL.Path, string(requestBody))
        logToFile("Response Body", r.Method, r.URL.Path, rr.Body.String())
    })
}

func logRequest(r *http.Request) ([]byte, error) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        log.Println("Error reading request body:", err)
        return nil, err
    }

    r.Body = io.NopCloser(bytes.NewBuffer(body))
    return body, nil
}

func logResponse(r *http.Request, rr *ResponseRecorder, duration time.Duration) {
    logData := fmt.Sprintf("Method: %s, Path: %s, Status: %d, Duration: %v\n",
        r.Method, r.URL.Path, rr.StatusCode, duration)
    fmt.Println(logData)

    if _, err := logFileWriter.WriteString(logData); err != nil {
        log.Printf("Error writing to log file: %v", err)
    }
    logFileWriter.Flush()
}

func logToFile(logType, method, path, body string) {
    logData := fmt.Sprintf("%s - %s %s %s\n", logType, method, path, body)
    fmt.Println(logData)

    if _, err := logFileWriter.WriteString(logData); err != nil {
        log.Printf("Error writing to log file: %v", err)
    }
    logFileWriter.Flush()
}


type Claims struct {
    Username string `json:"username"`
    jwt.RegisteredClaims
}


func GenerateJWT(username string) (string, error) {
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Username: username,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(expirationTime),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        return "", err
    }

    return tokenString, nil
}


func ValidateJWT(tokenStr string) (*Claims, error) {
    claims := &Claims{}

    token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
        
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return jwtKey, nil
    })

    if err != nil {
        return nil, err
    }

    if !token.Valid {
        return nil, errors.New("invalid token")
    }

    return claims, nil
}


func Login(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    
    storedUsername := "admin"
    storedPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

    if creds.Username != storedUsername || bcrypt.CompareHashAndPassword(storedPasswordHash, []byte(creds.Password)) != nil {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    token, err := GenerateJWT(creds.Username)
    if err != nil {
        http.Error(w, "Could not generate token", http.StatusInternalServerError)
        return
    }

    response := Response{
        Status:  "success",
        Message: "Authentication successful",
        Data: map[string]string{
            "token": token,
        },
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}


func JWTMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
            return
        }

        tokenStr := parts[1]
        claims, err := ValidateJWT(tokenStr)
        if err != nil {
            http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
            return
        }

        
        ctx := context.WithValue(r.Context(), "username", claims.Username)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}


func CreateStock(w http.ResponseWriter, r *http.Request) {
    var stock Stock
    if err := json.NewDecoder(r.Body).Decode(&stock); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if err := validate.Struct(stock); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    stock.CreatedAt = time.Now()
    stock.UpdatedAt = time.Now()

    
    additionalInfoJSON, err := json.Marshal(stock.AdditionalInfo)
    if err != nil {
        http.Error(w, "Invalid additional_info format", http.StatusBadRequest)
        return
    }
    stock.AdditionalInfo = datatypes.JSON(additionalInfoJSON)

    if err := db.Create(&stock).Error; err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    
    response := Response{
        Status:  "success",
        Message: "Stock created successfully",
        Data:    stock,
    }

    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)

    
    json.NewEncoder(w).Encode(response)
}


func UpdateStock(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := strconv.Atoi(params["id"])
    if err != nil {
        http.Error(w, "Invalid ID", http.StatusBadRequest)
        return
    }

    var stock Stock
    if err := db.First(&stock, id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            http.Error(w, "Stock not found", http.StatusNotFound)
        } else {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
        return
    }

    var updatedStock Stock
    if err := json.NewDecoder(r.Body).Decode(&updatedStock); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if err := validate.Struct(updatedStock); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    
    stock.NamaBarang = updatedStock.NamaBarang
    stock.JumlahStok = updatedStock.JumlahStok
    stock.NomorSeri = updatedStock.NomorSeri

    
    additionalInfoJSON, err := json.Marshal(updatedStock.AdditionalInfo)
    if err != nil {
        http.Error(w, "Invalid additional_info format", http.StatusBadRequest)
        return
    }
    stock.AdditionalInfo = datatypes.JSON(additionalInfoJSON)

    stock.GambarBarang = updatedStock.GambarBarang
    stock.UpdatedAt = time.Now()
    stock.UpdatedBy = updatedStock.UpdatedBy

    if err := db.Save(&stock).Error; err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    
    response := Response{
        Status:  "success",
        Message: "Stock updated successfully",
        Data:    stock,
    }

    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)

    
    json.NewEncoder(w).Encode(response)
}


func ListStocks(w http.ResponseWriter, r *http.Request) {
    pageQuery := r.URL.Query().Get("page")
    pageSizeQuery := r.URL.Query().Get("pageSize")

    page := 1
    pageSize := 10

    if pageQuery != "" {
        if p, err := strconv.Atoi(pageQuery); err == nil && p > 0 {
            page = p
        }
    }
    if pageSizeQuery != "" {
        if ps, err := strconv.Atoi(pageSizeQuery); err == nil && ps > 0 {
            pageSize = ps
        }
    }

    var stocks []Stock
    var totalItems int64

    db.Model(&Stock{}).Count(&totalItems)

    offset := (page - 1) * pageSize
    if err := db.Offset(offset).Limit(pageSize).Find(&stocks).Error; err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    totalPages := int(math.Ceil(float64(totalItems) / float64(pageSize)))

    response := map[string]interface{}{
        "data":       stocks,
        "page":       page,
        "pageSize":   pageSize,
        "totalItems": totalItems,
        "totalPages": totalPages,
    }

    standardResponse := Response{
        Status: "success",
        Data:   response,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(standardResponse)
}


func GetStockByID(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := strconv.Atoi(params["id"])
    if err != nil {
        http.Error(w, "Invalid ID", http.StatusBadRequest)
        return
    }

    var stock Stock
    result := db.First(&stock, id)

    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            http.Error(w, "Stock not found", http.StatusNotFound)
        } else {
            http.Error(w, result.Error.Error(), http.StatusInternalServerError)
        }
        return
    }

    var additionalInfo map[string]interface{}
    if err := json.Unmarshal(stock.AdditionalInfo, &additionalInfo); err != nil {
        http.Error(w, "Error parsing additional_info", http.StatusInternalServerError)
        return
    }
    stock.AdditionalInfo = datatypes.JSON(stock.AdditionalInfo)

    response := Response{
        Status: "success",
        Data:   stock,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}


func DeleteStock(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    id, err := strconv.Atoi(params["id"])
    if err != nil {
        http.Error(w, "Invalid ID", http.StatusBadRequest)
        return
    }

    result := db.Delete(&Stock{}, id)

    if result.Error != nil {
        http.Error(w, result.Error.Error(), http.StatusInternalServerError)
        return
    }

    if result.RowsAffected == 0 {
        http.Error(w, "Stock not found", http.StatusNotFound)
        return
    }
    
    response := Response{
        Status:  "success",
        Message: "Stock deleted successfully",
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    
    json.NewEncoder(w).Encode(response)
}

func main() {
    wd, err := os.Getwd()
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Current working directory: %s", wd)

    
    err = os.MkdirAll("logs", os.ModePerm)
    if err != nil {
        log.Fatal(err)
    }

    file, err := os.OpenFile("logs/api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
    if err != nil {
        log.Fatalf("Tidak bisa membuka atau membuat file log: %v", err)
    }
    defer file.Close()

    logFileWriter = bufio.NewWriter(file)
    
    initDB()

    r := mux.NewRouter()
    r.Use(LoggingMiddleware)
    r.HandleFunc("/login", Login).Methods("POST")
    protected := r.PathPrefix("/").Subrouter()
    protected.Use(JWTMiddleware)
    protected.HandleFunc("/stocks", CreateStock).Methods("POST")
    protected.HandleFunc("/stocks", ListStocks).Methods("GET")
    protected.HandleFunc("/stocks/{id}", GetStockByID).Methods("GET")
    protected.HandleFunc("/stocks/{id}", UpdateStock).Methods("PUT")
    protected.HandleFunc("/stocks/{id}", DeleteStock).Methods("DELETE")

    
    srv := &http.Server{
        Addr:    ":8080",
        Handler: r,
    }

    go func() {
        log.Println("Server running on port 8080")
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen: %s\n", err)
        }
    }()

    
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    log.Println("Shutting down server...")

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }

    log.Println("Server exiting")
}
