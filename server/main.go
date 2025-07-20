package main

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "github.com/gorilla/websocket"
    _ "github.com/mattn/go-sqlite3"
    "golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("9UltBRajmQbIhdd60TC5QTK3M92Ojo4XZSnSID/MtdE=") // 请换成自己的安全密钥

type Credentials struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type Claims struct {
    Username string `json:"username"`
    jwt.StandardClaims
}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { 
		origin := r.Header.Get("Origin")
        return origin == "https://secure.910602.xyz" }, // 生产环境改成可信域名检查
}

func main() {
    fmt.Println("🔐 Secure Chat Server Starting...")

    db, err := sql.Open("sqlite3", "./chat.db")
    if err != nil {
        log.Fatal("Database connection failed:", err)
    }
    defer db.Close()

    initDB(db)

    r := mux.NewRouter()

    r.HandleFunc("/api/register", registerHandler(db)).Methods("POST")
    r.HandleFunc("/api/login", loginHandler(db)).Methods("POST")

    // 受保护的 WebSocket 接口
    r.Handle("/ws", jwtMiddleware(http.HandlerFunc(wsHandler(db))))

    fmt.Println("✅ Server listening on :9909")
    log.Fatal(http.ListenAndServe(":9909", r))
}

func initDB(db *sql.DB) {
    db.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        pubkey TEXT
    )`)
    db.Exec(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT
    )`)
    db.Exec(`CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        user_id INTEGER
    )`)
    db.Exec(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        group_id INTEGER,
        receiver_id INTEGER,
        ciphertext TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`)
}

func registerHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var creds Credentials
        err := json.NewDecoder(r.Body).Decode(&creds)
        if err != nil || creds.Username == "" || creds.Password == "" {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
        if err != nil {
            http.Error(w, "Server error", http.StatusInternalServerError)
            return
        }

        _, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", creds.Username, string(hashedPassword))
        if err != nil {
            http.Error(w, "User already exists", http.StatusConflict)
            return
        }

        w.WriteHeader(http.StatusCreated)
    }
}

func loginHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var creds Credentials
        err := json.NewDecoder(r.Body).Decode(&creds)
        if err != nil {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }

        var storedHashedPassword string
        err = db.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&storedHashedPassword)
        if err != nil {
            http.Error(w, "User not found", http.StatusUnauthorized)
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(creds.Password))
        if err != nil {
            http.Error(w, "Incorrect password", http.StatusUnauthorized)
            return
        }

        expirationTime := time.Now().Add(24 * time.Hour)
        claims := &Claims{
            Username: creds.Username,
            StandardClaims: jwt.StandardClaims{
                ExpiresAt: expirationTime.Unix(),
            },
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        tokenString, err := token.SignedString(jwtKey)
        if err != nil {
            http.Error(w, "Server error", http.StatusInternalServerError)
            return
        }

        http.SetCookie(w, &http.Cookie{
            Name:    "token",
            Value:   tokenString,
            Expires: expirationTime,
            HttpOnly: true,
            Path:    "/",
        })

        w.Write([]byte(tokenString))
    }
}

func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("token")
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        tokenStr := cookie.Value
        claims := &Claims{}

        token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), "username", claims.Username)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func wsHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            http.Error(w, "Failed to upgrade", http.StatusInternalServerError)
            return
        }
        defer conn.Close()

        username := r.Context().Value("username").(string)
        fmt.Printf("WebSocket connected: %s\n", username)

        // 这里暂时简单打印客户端消息，后续可实现消息转发逻辑
        for {
            _, msg, err := conn.ReadMessage()
            if err != nil {
                fmt.Printf("WebSocket disconnected: %s\n", username)
                break
            }
            fmt.Printf("Recv from %s: %s\n", username, string(msg))

            // TODO: 根据消息内容解析转发给目标用户或群组
        }
    }
}
