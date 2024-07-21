package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/catalinc/hashcash"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/scrypt"
)

var (
	conn       *sql.DB
	mem        *sql.DB
	host       string
	port       int
	secretKey  string
	maxStorage int64
	saltChars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func randomChars(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("salt length must be at least one")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	for i := range salt {
		salt[i] = saltChars[int(randomBytes[i])%len(saltChars)]
	}
	return string(salt), nil
}

func hash(password, salt string) (string, error) {
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)

	derivedKey, err := scrypt.Key(passwordBytes, saltBytes, 32768, 8, 1, 64)
	if err != nil {
		return "", err
	}

	hashString := fmt.Sprintf("scrypt:32768:8:1$%s$%s", salt, hex.EncodeToString(derivedKey))
	return hashString, nil
}

func verifyHash(werkzeugHash, password string) (bool, error) {
	parts := strings.Split(werkzeugHash, "$")
	if len(parts) != 3 || parts[0] != "scrypt:32768:8:1" {
		return false, errors.New("invalid hash format")
	}
	salt := parts[1]

	computedHash, err := hash(password, salt)
	if err != nil {
		return false, err
	}

	return werkzeugHash == computedHash, nil
}

func getUser(id int) (string, string, string, error) {
	var created, username, password string
	err := conn.QueryRow("SELECT created, username, password FROM users WHERE id = ? LIMIT 1", id).Scan(&created, &username, &password)
	if err != nil {
		return "", "", "", err
	}

	return created, username, password, err
}

func getNote(id int) (int, string, string, string, string, error) {
	var creator int
	var created, edited, content, title string
	err := conn.QueryRow("SELECT creator, created, edited, content, title FROM notes WHERE id = ? LIMIT 1", id).Scan(&creator, &created, &edited, &content, &title)
	if err != nil {
		return 0, "", "", "", "", err
	}

	return creator, created, edited, content, title, err
}

func getSpace(id int) (int, error) {
	var space int
	err := conn.QueryRow("SELECT COALESCE(SUM(LENGTH(content) + LENGTH(title)), 0) FROM notes WHERE creator = ?", id).Scan(&space)
	if err != nil {
		return 0, err
	}
	return space, nil
}

func getNoteCount(id int) (int, error) {
	var count int
	err := conn.QueryRow("SELECT COUNT(*) FROM notes WHERE creator = ?", id).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func checkUsernameTaken(username string) (int, bool, error) {
	var id int
	err := conn.QueryRow("SELECT id FROM users WHERE lower(username) = ? LIMIT 1", strings.ToLower(username)).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		} else {
			return 0, true, err
		}
	} else {
		return id, true, nil
	}
}

func getSession(session string) (int, int, error) {
	var id int
	var sessionId int
	err := mem.QueryRow("SELECT sessionid, id FROM sessions WHERE session = ? LIMIT 1", session).Scan(&sessionId, &id)
	if err != nil {
		return 0, 0, err
	}
	return sessionId, id, err
}

func getSessionFromId(sessionId int) (string, int, error) {
	var id int
	var session string
	err := mem.QueryRow("SELECT session, id FROM sessions WHERE sessionid = ? LIMIT 1", sessionId).Scan(&session, &id)
	if err != nil {
		return "", 0, err
	}
	return session, id, err
}

func generateDB() error {
	schemaBytes, err := os.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	_, err = conn.Exec(string(schemaBytes))
	if err != nil {
		return err
	}
	log.Println("[INFO] Generated database")
	return nil
}

func initDb() {
	_, err := os.Stat("database.db")
	if os.IsNotExist(err) {
		err = generateDB()
		if err != nil {
			log.Fatalln("[FATAL] Unknown while generating database:", err)
		}
	} else {
		log.Print("[PROMPT] Proceeding will overwrite the database. Proceed? (y/n): ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Fatalln("[FATAL] Unknown while scanning input:", err)
		}
		if strings.ToLower(answer) == "y" {
			err := generateDB()
			if err != nil {
				log.Fatalln("[FATAL] Unknown while generating database:", err)
				return
			}
		} else if answer == ":3" {
			log.Println("[:3] :3")
		} else {
			log.Println("[INFO] Stopped")
		}
	}
}

func migrateDb() {
	_, err := os.Stat("database.db")
	if os.IsNotExist(err) {
		err = generateDB()
		if err != nil {
			log.Fatalln("[FATAL] Unknown while generating database:", err)
		}
	} else {
		log.Println("[PROMPT] Proceeding will render the database unusable for older versions of Burgernotes. Proceed? (y/n): ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Fatalln("[FATAL] Unknown while scanning input:", err)
		}
		if strings.ToLower(answer) == "y" {
			_, err = conn.Exec("ALTER TABLE users DROP COLUMN versionTwoLegacyPassword")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (1/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, and Burgernotes does not need this removed - it is just for cleanup")
			}
			_, err = conn.Exec("CREATE TABLE oauth (id INTEGER NOT NULL, oauthProvider TEXT NOT NULL, encryptedPasswd TEXT NOT NULL)")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (2/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, but if it is not, it may cause issues with OAuth2")
			}
			_, err = conn.Exec("DROP TABLE sessions")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (3/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, and Burgernotes does not need this removed - it is just for cleanup")
			}
			_, err = conn.Exec("ALTER TABLE users ADD COLUMN migrated INTEGER NOT NULL DEFAULT 0")
			if err != nil {
				log.Println("[WARN] Unknown while migrating database (4/4):", err)
				log.Println("[INFO] This is likely because your database is already migrated. This is not a problem, but if it is not, it may cause issues with migrating to Burgernotes 2.0")
			}
		} else if answer == ":3" {
			log.Println("[:3] :3")
		} else {
			log.Println("[INFO] Stopped")
		}
	}
}

func main() {
	if _, err := os.Stat("config.ini"); err == nil {
		log.Println("[INFO] Config loaded at", time.Now().Unix())
	} else if os.IsNotExist(err) {
		log.Fatalln("[FATAL] config.ini does not exist")
	} else {
		log.Fatalln("[FATAL] File is in quantum uncertainty:", err)
	}

	viper.SetConfigName("config")
	viper.AddConfigPath("./")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalln("[FATAL] Error in config file:", err)
	}

	host = viper.GetString("config.HOST")
	port = viper.GetInt("config.PORT")
	secretKey = viper.GetString("config.SECRET_KEY")
	maxStorage = viper.GetInt64("config.MAX_STORAGE")

	if host == "" {
		log.Fatalln("[FATAL] HOST is not set")
	}

	if port == 0 {
		log.Fatalln("[FATAL] PORT is not set")
	}

	if secretKey == "" {
		log.Fatalln("[FATAL] SECRET_KEY is not set")
	} else if secretKey == "supersecretkey" {
		log.Println("[WARN] SECRET_KEY is set to a default value. Please set it to another value.")
	}

	if maxStorage == 0 {
		log.Fatalln("[FATAL] MAX_STORAGE is not set")
	}

	conn, err = sql.Open("sqlite3", "database.db")
	if err != nil {
		log.Fatalln("[FATAL] Cannot open database:", err)
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() conn defer:", err)
		}
	}(conn)

	mem, err = sql.Open("sqlite3", ":memory: cache=shared")
	if err != nil {
		log.Fatalln("[FATAL] Cannot open session database:", err)
	}
	defer func(mem *sql.DB) {
		err := mem.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() mem defer:", err)
		}
	}(mem)

	_, err = mem.Exec("CREATE TABLE sessions (sessionid INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL, id INTEGER NOT NULL, device TEXT NOT NULL DEFAULT '?')")
	if err != nil {
		if err.Error() == "table sessions already exists" {
			log.Println("[INFO] Session table already exists")
		} else {
			log.Fatalln("[FATAL] Cannot create session table:", err)
		}
	}

	if len(os.Args) > 1 {
		if os.Args[1] == "init_db" {
			initDb()
			os.Exit(0)
		} else if os.Args[1] == "migrate_db" {
			migrateDb()
			os.Exit(0)
		}
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	store := cookie.NewStore([]byte(secretKey))
	router.Use(sessions.Sessions("session", store))

	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "*")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	})

	router.GET("/api/version", func(c *gin.Context) {
		c.String(200, "Burgernotes Version 2.0 Beta 2")
	})

	router.GET("/api/versionjson", func(c *gin.Context) {
		c.JSON(200, gin.H{"name": "Burgernotes", "versiontxt": "Version 2.0 Beta 2", "versionsem": "2.0.0b2", "versionnum": "200"})
	})

	router.POST("/api/signup", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username, ok := data["username"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		password, ok := data["password"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		stamp, ok := data["stamp"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		pow := hashcash.New(20, 16, "I love burgernotes!")
		ok = pow.Check(stamp)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid hashcash stamp"})
			return
		}

		if username == "" || password == "" || len(username) > 20 || !regexp.MustCompile("^[a-zA-Z0-9]+$").MatchString(username) {
			c.JSON(422, gin.H{"error": "Invalid username or password"})
			return
		}

		_, taken, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup checkUsernameTaken():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-USERTAKEN"})
			return
		}
		if taken {
			c.JSON(409, gin.H{"error": "Username is taken"})
			return
		}

		salt, err := randomChars(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SALT"})
			return
		}
		hashedPasswd, err := hash(password, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup hash():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-HASH"})
			return
		}

		_, err = conn.Exec("INSERT INTO users (username, password, created, migrated) VALUES (?, ?, ?, 1)", username, hashedPasswd, strconv.FormatInt(time.Now().Unix(), 10))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-DBINSERT"})
			return
		}

		log.Println("[INFO] Added new user at", time.Now().Unix())
		userid, taken, err := checkUsernameTaken(username)
		if !taken {
			log.Println("[CRITICAL] Something is very wrong! A user was created but could not be found in the database at", time.Now().Unix())
			log.Println("[INFO] This should not be possible. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes with the error code: UNKNOWN-API-SIGNUP-POSTTAKEN")
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-POSTTAKEN"})
			return
		}

		token, err := randomChars(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup token randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONSALT"})
			return
		}
		_, err = mem.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", token, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup session Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONINSERT"})
			return
		}

		c.JSON(200, gin.H{"key": token})
	})

	router.POST("/api/login", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username, ok := data["username"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		password, ok := data["password"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		userid, taken, err := checkUsernameTaken(username)
		if !taken {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /api/login checkUsernameTaken():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-USERTAKEN"})
			return
		}

		var migrated int
		err = conn.QueryRow("SELECT migrated FROM users WHERE id = ?", userid).Scan(&migrated)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login migrated QueryRow():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-MIGRATED"})
			return
		}

		_, _, hashedPasswd, err := getUser(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login getUser():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-GETUSER"})
			return
		}

		correctPassword, err := verifyHash(hashedPasswd, password)
		if err != nil {
			if errors.Is(err, errors.New("invalid hash format")) {
				c.JSON(422, gin.H{"error": "Invalid hash format"})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/login verifyHash():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-VERIFYHASH"})
				return
			}
		}
		if !correctPassword {
			if migrated == 0 {
				c.JSON(401, gin.H{"error": "User has not migrated", "migrated": false})
				return
			} else {
				c.JSON(401, gin.H{"error": "Incorrect password", "migrated": true})
				return
			}
		}

		token, err := randomChars(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login token randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONSALT"})
			return
		}

		_, err = mem.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", token, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login session Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONINSERT"})
			return
		}

		c.JSON(200, gin.H{"key": token})
	})

	router.POST("/api/oauth/get", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username, ok := data["username"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		oauthProvider, ok := data["oauthProvider"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := checkUsernameTaken(username)
		if err != nil {
			c.JSON(404, gin.H{"error": "Username not found"})
			return
		}

		var encryptedPasswd string
		err = conn.QueryRow("SELECT encryptedPasswd FROM oauth WHERE id = ? AND oauthProvider = ?", userid, oauthProvider).Scan(&encryptedPasswd)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(404, gin.H{"error": "Entry not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/oauth/get select:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-OAUTH-GET-SELECT"})
			}
		}

		c.JSON(200, gin.H{"password": encryptedPasswd})
	})

	router.POST("/api/oauth/add", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		oauthProvider, ok := data["oauthProvider"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		encryptedPassword, ok := data["encryptedPassword"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("INSERT INTO oauth (id, oauthProvider, encryptedPasswd) VALUES (?, ?, ?)", userid, oauthProvider, encryptedPassword)
		if err != nil {
			if errors.Is(err, sqlite3.ErrConstraintUnique) {
				c.JSON(409, gin.H{"error": "Entry already exists"})
			} else {
				log.Println("[ERROR] Unknown in /api/oauth/add Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-OAUTH-ADD-EXEC"})
			}
		}

		c.JSON(200, gin.H{"success": true})
	})

	router.POST("/api/oauth/remove", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		oauthProvider, ok := data["oauthProvider"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("DELETE FROM oauth WHERE userid = ? AND oauthProvider = ?", userid, oauthProvider)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(404, gin.H{"error": "Entry not found"})
			} else {
				log.Println("[ERROR] Unknown in /api/oauth/add Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-OAUTH-REMOVE-EXEC"})
			}
		}

		c.JSON(200, gin.H{"success": true})
	})

	router.POST("/api/changepassword", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		newPassword, ok := data["newPassword"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		salt, err := randomChars(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword randomChars():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-SALT"})
			return
		}
		hashedPassword, err := hash(newPassword, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword hash():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-HASH"})
			return
		}

		_, err = conn.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-DBUPDATE"})
			return
		}

		c.JSON(200, gin.H{"success": true})
	})

	router.POST("/api/userinfo", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		created, username, _, err := getUser(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getUser():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-USERINFO-GETUSER"})
			return
		}

		space, err := getSpace(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getSpace():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-USERINFO-GETSPACE"})
			return
		}

		notecount, err := getNoteCount(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getNoteCount():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-USERINFO-GETNOTECOUNT"})
			return
		}
		c.JSON(200, gin.H{"username": username, "id": userid, "created": created, "storageused": space, "storagemax": maxStorage, "notecount": notecount})
	})

	router.POST("/api/loggedin", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}
		if userid > 0 {
			c.JSON(200, gin.H{"loggedin": true})
		} else {
			c.JSON(403, gin.H{"loggedin": false})
		}
	})

	router.POST("/api/listnotes", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		rows, err := conn.Query("SELECT id, title FROM notes WHERE creator = ? ORDER BY id DESC", userid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(200, []map[string]interface{}{})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/listnotes query:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-DBQUERY"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/listnotes row defer:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-ROWCLOSE"})
				return
			}
		}(rows)

		var notes []map[string]interface{}
		for rows.Next() {
			var id int
			var title string
			if err := rows.Scan(&id, &title); err != nil {
				log.Println("[ERROR] Unknown in /api/listnotes row scan:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-ROWSCAN"})
				return
			}
			notes = append(notes, map[string]interface{}{"id": id, "title": title})
		}
		if err := rows.Err(); err != nil {
			log.Println("[ERROR] Unknown in /api/listnotes row iteration:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-ROWERR"})
			return
		}

		c.JSON(200, notes)
	})

	router.POST("/api/exportnotes", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		rows, err := conn.Query("SELECT id, created, edited, title, content FROM notes WHERE creator = ? ORDER BY edited DESC", userid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(200, []map[string]interface{}{})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/exportnotes query:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-DBQUERY"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/exportnotes row defer:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-ROWCLOSE"})
				return
			}
		}(rows)

		var notes []map[string]interface{}
		for rows.Next() {
			var id int
			var created, edited, title, content string
			if err := rows.Scan(&id, &created, &edited, &title, &content); err != nil {
				log.Println("[ERROR] Unknown in /api/exportnotes row scan:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-ROWSCAN"})
				return
			}
			notes = append(notes, map[string]interface{}{"id": id, "created": created, "edited": edited, "title": title, "content": content})
		}
		if err := rows.Err(); err != nil {
			log.Println("[ERROR] Unknown in /api/exportnotes row iteration:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-ROWERR"})
			return
		}

		c.JSON(200, notes)
	})

	router.POST("/api/importnotes", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		notesStr, ok := data["notes"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		var notes []interface{}
		err = json.Unmarshal([]byte(notesStr), &notes)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		for _, note := range notes {
			note := note.(map[string]interface{})
			_, err := conn.Exec("INSERT INTO notes (creator, created, edited, title, content) VALUES (?, ?, ?, ?, ?)", userid, note["created"], note["edited"], note["title"], note["content"])
			if err != nil {
				log.Println("[ERROR] Unknown in /api/importnotes Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-IMPORTNOTES-DBINSERT"})
				return
			}
		}

		c.JSON(200, gin.H{"success": true})
	})

	router.POST("/api/newnote", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteName, ok := data["noteName"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		space, err := getSpace(userid)
		if int64(len(noteName)+space) > maxStorage {
			c.JSON(403, gin.H{"error": "Storage limit reached"})
			return
		} else {
			_, err := conn.Exec("INSERT INTO notes (title, content, creator, created, edited) VALUES (?, ?, ?, ?, ?)", noteName, "", userid, strconv.FormatInt(time.Now().Unix(), 10), strconv.FormatInt(time.Now().Unix(), 10))
			if err != nil {
				log.Println("[ERROR] Unknown in /api/newnote Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-NEWNOTE-DBINSERT"})
				return
			} else {
				c.JSON(200, gin.H{"success": true})
			}
		}
	})

	router.POST("/api/readnote", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteIdFloat, ok := data["noteId"].(float64)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteId := int(noteIdFloat)

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		creator, _, _, content, _, err := getNote(noteId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "Note not found"})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/readnote getNote():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-READNOTE-GETNOTE"})
				return
			}
		} else {
			if creator != userid {
				c.JSON(422, gin.H{"error": "Note does not belong to user"})
				return
			} else {
				c.JSON(200, gin.H{"content": content})
			}
		}
	})

	router.POST("/api/purgenotes", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("DELETE FROM notes WHERE creator = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/purgenotes Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-PURGENOTES-DBDELETE"})
			return
		} else {
			c.JSON(200, gin.H{"success": true})
		}
	})

	router.POST("/api/editnote", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteIdFloat, ok := data["noteId"].(float64)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteId := int(noteIdFloat)
		content, ok := data["content"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		title, ok := data["title"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		creator, _, _, _, _, err := getNote(noteId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "Note not found"})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/editnote getNote():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EDITNOTE-GETNOTE"})
				return
			}
		}

		if creator != userid {
			c.JSON(403, gin.H{"error": "Note does not belong to user"})
			return
		} else {
			_, err := conn.Exec("UPDATE notes SET content = ?, title = ?, edited = ? WHERE id = ?", content, title, strconv.FormatInt(time.Now().Unix(), 10), noteId)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/editnote Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EDITNOTE-DBUPDATE"})
				return
			} else {
				c.JSON(200, gin.H{"success": true})
			}
		}
	})

	router.POST("/api/removenote", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteIdFloat, ok := data["noteId"].(float64)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		noteId := int(noteIdFloat)

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		creator, _, _, _, _, err := getNote(noteId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "Note not found"})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/removenote getNote():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-REMOVENOTE-GETNOTE"})
				return
			}
		}

		if creator != userid {
			c.JSON(403, gin.H{"error": "Note does not belong to user"})
			return
		} else {
			_, err := conn.Exec("DELETE FROM notes WHERE id = ?", noteId)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/removenote Exec():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-REMOVENOTE-DBDELETE"})
				return
			} else {
				c.JSON(200, gin.H{"success": true})
			}
		}
	})

	router.POST("/api/deleteaccount", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("DELETE FROM notes WHERE creator = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/deleteaccount notes Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-DELETEACCOUNT-NOTESDELETE"})
			return
		}

		_, err = conn.Exec("DELETE FROM users WHERE id = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/deleteaccount user Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-DELETEACCOUNT-USERDELETE"})
			return
		}

		_, err = mem.Exec("DELETE FROM sessions WHERE id = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/deleteaccount session Exec():", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-DELETEACCOUNT-SESSIONDELETE"})
			return
		}

		c.JSON(200, gin.H{"success": true})
	})

	router.POST("/api/sessions/list", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		rows, err := mem.Query("SELECT sessionid, session, device FROM sessions WHERE id = ? ORDER BY id DESC", userid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(200, []map[string]interface{}{})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/sessions/list query:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-DBQUERY"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list row defer:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-ROWCLOSE"})
				return
			}
		}(rows)

		var sessionList []map[string]interface{}
		for rows.Next() {
			var sessionid int
			var session, device string
			if err := rows.Scan(&sessionid, &session, &device); err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list row scan:", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-ROWSCAN"})
				return
			}
			if session == token {
				sessionList = append(sessionList, map[string]interface{}{"id": sessionid, "thisSession": true, "device": device})
			} else {
				sessionList = append(sessionList, map[string]interface{}{"id": sessionid, "thisSession": false, "device": device})
			}
		}
		if err := rows.Err(); err != nil {
			log.Println("[ERROR] Unknown in /api/sessions/list row iteration:", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-ROWERR"})
			return
		}

		c.JSON(200, sessionList)
	})

	router.POST("/api/sessions/remove", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token, ok := data["secretKey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		sessionIdFloat, ok := data["sessionId"].(float64)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		sessionId := int(sessionIdFloat)

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, creator, err := getSessionFromId(sessionId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(422, gin.H{"error": "Target session not found"})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/sessions/remove getSession():", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-REMOVE-GETSESSION"})
				return
			}
		} else {
			if creator != userid {
				c.JSON(403, gin.H{"error": "Session does not belong to user"})
				return
			} else {
				_, err := mem.Exec("DELETE FROM sessions WHERE sessionid = ?", sessionId)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/sessions/remove Exec():", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-REMOVE-DBDELETE"})
					return
				} else {
					c.JSON(200, gin.H{"success": true})
				}
			}
		}
	})

	router.POST("/api/listusers", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		masterToken, ok := data["masterkey"].(string)
		if !ok {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}
		if masterToken == secretKey {
			rows, err := conn.Query("SELECT id, username, created FROM users ORDER BY id DESC")
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.JSON(200, []map[string]interface{}{})
					return
				} else {
					log.Println("[ERROR] Unknown in /api/listusers query:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-DBQUERY"})
					return
				}
			}
			defer func(rows *sql.Rows) {
				err := rows.Close()
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers row defer:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-ROWCLOSE"})
					return
				}
			}(rows)

			var users []map[string]interface{}
			for rows.Next() {
				var id int
				var username, created string
				if err := rows.Scan(&id, &username, &created); err != nil {
					log.Println("[ERROR] Unknown in /api/listusers row scan:", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-ROWSCAN"})
					return
				}
				space, err := getSpace(id)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers getSpace():", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-GETSPACE"})
					return
				}
				notes, err := getNoteCount(id)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers getNoteCount():", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-GETNOTECOUNT"})
					return
				}
				users = append(users, map[string]interface{}{"id": id, "username": username, "created": created, "space": space, "notes": notes})
			}
			if err := rows.Err(); err != nil {
				log.Println("[ERROR] Unknown in /api/listusers row iteration:", err)
			}
		}
	})

	log.Println("[INFO] Server started at", time.Now().Unix())
	log.Println("[INFO] Welcome to Burgernotes! Today we are running on IP " + host + " on port " + strconv.Itoa(port) + ".")
	err = router.Run(host + ":" + strconv.Itoa(port))
	if err != nil {
		log.Fatalln("[FATAL] Server failed to begin operations at", time.Now().Unix(), err)
	}
}
