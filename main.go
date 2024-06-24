package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

var (
	conn       *sql.DB
	host       string
	port       int
	secretKey  string
	maxStorage int64
	saltChars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func genSalt(length int) (string, error) {
	if length <= 0 {
		log.Println("[ERROR] Known in genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", "Salt length must be at least one.")
	}

	salt := make([]byte, length)
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Println("[ERROR] Unknown in genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		return "", err
	}

	for i := range salt {
		salt[i] = saltChars[int(randomBytes[i])%len(saltChars)]
	}
	return string(salt), nil
}

func hashSha3(iterations int, input string) string {
	key := input
	for i := 0; i < iterations; i++ {
		hash := sha3.New512()
		hash.Write([]byte(key))
		keyBytes := hash.Sum(nil)
		key = hex.EncodeToString(keyBytes)
	}
	return key
}

func hash(password, salt string) (string, error) {
	passwordBytes := []byte(password)
	saltBytes := []byte(salt)

	derivedKey, err := scrypt.Key(passwordBytes, saltBytes, 32768, 8, 1, 64)
	if err != nil {
		log.Println("[ERROR] Unknown in hash() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
	err := conn.QueryRow("SELECT sessionid, id FROM sessions WHERE session = ? LIMIT 1", session).Scan(&sessionId, &id)
	if err != nil {
		return 0, 0, err
	}
	return sessionId, id, err
}

func getSessionFromId(sessionId int) (string, int, error) {
	var id int
	var session string
	err := conn.QueryRow("SELECT session, id FROM sessions WHERE sessionid = ? LIMIT 1", sessionId).Scan(&session, &id)
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
			log.Fatalln("[FATAL] Unknown while generating database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	} else {
		log.Print("[PROMPT] Proceeding will overwrite the database. Proceed? (y/n): ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Fatalln("[FATAL] Unknown while scanning input at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
		if strings.ToLower(answer) == "y" {
			err := generateDB()
			if err != nil {
				log.Fatalln("[FATAL] Unknown while generating database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
			log.Fatalln("[FATAL] Unknown while generating database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	} else {
		log.Println("[PROMPT] Proceeding will render the database unusable for older versions of Burgernotes. Proceed? (y/n): ")
		var answer string
		_, err := fmt.Scanln(&answer)
		if err != nil {
			log.Fatalln("[FATAL] Unknown while scanning input at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
		if strings.ToLower(answer) == "y" {
			_, err := conn.Exec("ALTER TABLE users ADD COLUMN versionTwoLegacyPassword TEXT NOT NULL DEFAULT 'nil'")
			if err != nil {
				log.Fatalln("[FATAL] Unknown while migrating database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				return
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
		log.Fatalln("[FATAL] Error in config file at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
		log.Fatalln("[FATAL] Cannot open database at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {
			log.Println("[ERROR] Unknown in main() defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
		}
	}(conn)

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
		c.String(200, "Burgernotes Version 2.0 Beta 1")
	})

	router.POST("/api/signup", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		username := data["username"].(string)
		password := data["password"].(string)

		enableAPIVersion2 := false
		versionCheck := c.GetHeader("X-Burgernotes-Version")
		if versionCheck != "" {
			versionCheckInt, err := strconv.Atoi(versionCheck)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login versionCheck at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-VERSIONCHECK"})
				return
			}
			if versionCheckInt > 199 {
				enableAPIVersion2 = true
			}
		}

		if username == "" || password == "" || len(username) > 20 || !regexp.MustCompile("^[a-zA-Z0-9]+$").MatchString(username) {
			c.JSON(422, gin.H{"error": "Invalid username or password"})
			return
		}

		_, taken, err := checkUsernameTaken(username)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup checkUsernameTaken() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-USERTAKEN"})
			return
		}
		if taken {
			c.JSON(409, gin.H{"error": "Username is taken"})
			return
		}

		salt, err := genSalt(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SALT"})
			return
		}
		hashedPasswd, err := hash(password, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup hash() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-HASH"})
			return
		}

		if !enableAPIVersion2 {
			_, err = conn.Exec("INSERT INTO users (username, password, versionTwoLegacyPassword, created) VALUES (?, ?, ?)", username, hashedPasswd, "nil", strconv.FormatInt(time.Now().Unix(), 10))
		} else {
			legacyPassword := data["legacyPassword"].(string)
			_, err = conn.Exec("INSERT INTO users (username, password, versionTwoLegacyPassword, created) VALUES (?, ?, ?)", username, hashedPasswd, legacyPassword, strconv.FormatInt(time.Now().Unix(), 10))
		}

		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup token genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SIGNUP-SESSIONSALT"})
			return
		}
		_, err = conn.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", token, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/signup session Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		enableAPIVersion2 := false
		enableAPIVersion1 := false
		version1PasswordChange := data["passwordchange"].(string)
		versionCheck := c.GetHeader("X-Burgernotes-Version")
		if versionCheck != "" {
			versionCheckInt, err := strconv.Atoi(versionCheck)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login versionCheck at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-VERSIONCHECK"})
				return
			}
			if versionCheckInt > 199 {
				enableAPIVersion2 = true
			}
		} else {
			if version1PasswordChange != "" {
				enableAPIVersion1 = true
			} else {
				enableAPIVersion1 = false
			}
		}

		username := data["username"].(string)
		password := data["password"].(string)

		userid, taken, err := checkUsernameTaken(username)
		if !taken {
			c.JSON(401, gin.H{"error": "User does not exist"})
			return
		} else if err != nil {
			log.Println("[ERROR] Unknown in /api/login checkUsernameTaken() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-USERTAKEN"})
			return
		}

		if enableAPIVersion1 || version1PasswordChange != "" {
			salt, err := genSalt(16)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-SALT"})
				return
			}
			hashedPassword, err := hash(version1PasswordChange, salt)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login hash() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-HASH"})
				return
			}
			_, err = conn.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userid)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-DBUPDATE"})
				return
			}
		}

		if enableAPIVersion2 || enableAPIVersion1 {
			_, _, hashedPasswd, err := getUser(userid)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-GETUSER"})
				return
			}

			correctPassword, err := verifyHash(hashedPasswd, password)
			if err != nil {
				if errors.Is(err, errors.New("invalid hash format")) {
					c.JSON(422, gin.H{"error": "Invalid hash format"})
					return
				} else {
					log.Println("[ERROR] Unknown in /api/login verifyHash() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-VERIFYHASH"})
					return
				}
			}
			if !correctPassword {
				c.JSON(401, gin.H{"error": "Incorrect password"})
				return
			}
		} else {
			var legacyPassword string
			err = conn.QueryRow("SELECT versionTwoLegacyPassword FROM users WHERE id = ?", userid).Scan(&legacyPassword)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login legacyPassword query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-LEGACYQUERY"})
				return
			}
			hashedPassword := hashSha3(128, password)

			correctPassword, err := verifyHash(hashedPassword, password)
			if err != nil {
				if errors.Is(err, errors.New("invalid hash format")) {
					c.JSON(422, gin.H{"error": "Invalid hash format"})
					return
				} else {
					log.Println("[ERROR] Unknown in /api/login verifyHash() legacy at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-VERIFYHASH"})
					return
				}
			}

			if !correctPassword {
				c.JSON(401, gin.H{"error": "Incorrect password"})
				return
			}
		}

		token, err := genSalt(512)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login token genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONSALT"})
			return
		}

		_, err = conn.Exec("INSERT INTO sessions (session, id, device) VALUES (?, ?, ?)", token, userid, c.Request.Header.Get("User-Agent"))
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login session Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-SESSIONINSERT"})
			return
		}

		if enableAPIVersion2 {
			var legacyPassword string
			err = conn.QueryRow("SELECT versionTwoLegacyPassword FROM users WHERE id = ?", userid).Scan(&legacyPassword)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login legacyPassword query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-LEGACYQUERY"})
				return
			}
			if legacyPassword != "nil" {
				c.JSON(200, gin.H{"key": token, "legacyPasswordNeeded": true})
			} else {
				c.JSON(200, gin.H{"key": token, "legacyPasswordNeeded": false})
			}
			return
		} else {
			c.JSON(200, gin.H{"key": token})
		}
	})

	router.POST("/api/v2/addlegacypassword", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		versionCheck := c.GetHeader("X-Burgernotes-Version")
		if versionCheck != "" {
			versionCheckInt, err := strconv.Atoi(versionCheck)
			if err != nil {
				log.Println("[ERROR] Unknown in /api/login versionCheck at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-ADDLEGACYPASSWORD-VERSIONCHECK"})
				return
			}
			if versionCheckInt < 200 {
				c.JSON(400, gin.H{"error": "This API can only be accessed by Burgernotes 2.0 and above"})
				return
			}
		} else {
			c.JSON(400, gin.H{"error": "This API can only be accessed by Burgernotes 2.0 and above"})
			return
		}

		token := data["secretKey"].(string)
		legacyPassword := data["legacyPassword"].(string)
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("UPDATE users SET versionTwoLegacyPassword = ? WHERE id = ?", legacyPassword, userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/login/addlegacypassword Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LOGIN-ADDLEGACYPASSWORD"})
			return
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

		token := data["secretKey"].(string)
		newPassword := data["newPassword"].(string)

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		salt, err := genSalt(16)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword genSalt() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-SALT"})
			return
		}
		hashedPassword, err := hash(newPassword, salt)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword hash() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-CHANGEPASSWORD-HASH"})
			return
		}

		_, err = conn.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/changepassword Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		created, username, _, err := getUser(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getUser() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-USERINFO-GETUSER"})
			return
		}

		space, err := getSpace(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getSpace() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-USERINFO-GETSPACE"})
			return
		}

		notecount, err := getNoteCount(userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/userinfo getNoteCount() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
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

		token := data["secretKey"].(string)
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
				log.Println("[ERROR] Unknown in /api/listnotes query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-DBQUERY"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/listnotes row defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-ROWCLOSE"})
				return
			}
		}(rows)

		var notes []map[string]interface{}
		for rows.Next() {
			var id int
			var title string
			if err := rows.Scan(&id, &title); err != nil {
				log.Println("[ERROR] Unknown in /api/listnotes row scan at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTNOTES-ROWSCAN"})
				return
			}
			notes = append(notes, map[string]interface{}{"id": id, "title": title})
		}
		if err := rows.Err(); err != nil {
			log.Println("[ERROR] Unknown in /api/listnotes row iteration at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
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
				log.Println("[ERROR] Unknown in /api/exportnotes query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-DBQUERY"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/exportnotes row defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-ROWCLOSE"})
				return
			}
		}(rows)

		var notes []map[string]interface{}
		for rows.Next() {
			var id int
			var created, edited, title, content string
			if err := rows.Scan(&id, &created, &edited, &title, &content); err != nil {
				log.Println("[ERROR] Unknown in /api/exportnotes row scan at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-EXPORTNOTES-ROWSCAN"})
				return
			}
			notes = append(notes, map[string]interface{}{"id": id, "created": created, "edited": edited, "title": title, "content": content})
		}
		if err := rows.Err(); err != nil {
			log.Println("[ERROR] Unknown in /api/exportnotes row iteration at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
		notesStr := data["notes"].(string)

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
				log.Println("[ERROR] Unknown in /api/importnotes Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
		noteName := data["noteName"].(string)
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
				log.Println("[ERROR] Unknown in /api/newnote Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
		noteId := int(data["noteId"].(float64))

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
				log.Println("[ERROR] Unknown in /api/readnote getNote() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

	router.POST("/api/editnote", func(c *gin.Context) {
		var data map[string]interface{}
		err := c.ShouldBindJSON(&data)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		token := data["secretKey"].(string)
		noteId := int(data["noteId"].(float64))
		content := data["content"].(string)
		title := data["title"].(string)

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
				log.Println("[ERROR] Unknown in /api/editnote getNote() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
				log.Println("[ERROR] Unknown in /api/editnote Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
		noteId := int(data["noteId"].(float64))

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
				log.Println("[ERROR] Unknown in /api/removenote getNote() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
				log.Println("[ERROR] Unknown in /api/removenote Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		_, err = conn.Exec("DELETE FROM notes WHERE creator = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/deleteaccount notes Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-DELETEACCOUNT-NOTESDELETE"})
			return
		}

		_, err = conn.Exec("DELETE FROM users WHERE id = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/deleteaccount user Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
			c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-DELETEACCOUNT-USERDELETE"})
			return
		}

		_, err = conn.Exec("DELETE FROM sessions WHERE id = ?", userid)
		if err != nil {
			log.Println("[ERROR] Unknown in /api/deleteaccount session Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)

		_, userid, err := getSession(token)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid session"})
			return
		}

		rows, err := conn.Query("SELECT sessionid, session, device FROM sessions WHERE id = ? ORDER BY id DESC", userid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(200, []map[string]interface{}{})
				return
			} else {
				log.Println("[ERROR] Unknown in /api/sessions/list query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-DBQUERY"})
				return
			}
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list row defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-LIST-ROWCLOSE"})
				return
			}
		}(rows)

		var sessionList []map[string]interface{}
		for rows.Next() {
			var sessionid int
			var session, device string
			if err := rows.Scan(&sessionid, &session, &device); err != nil {
				log.Println("[ERROR] Unknown in /api/sessions/list row scan at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
			log.Println("[ERROR] Unknown in /api/sessions/list row iteration at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		token := data["secretKey"].(string)
		sessionId := int(data["sessionId"].(float64))

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
				log.Println("[ERROR] Unknown in /api/sessions/remove getSession() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
				c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-SESSIONS-REMOVE-GETSESSION"})
				return
			}
		} else {
			if creator != userid {
				c.JSON(403, gin.H{"error": "Session does not belong to user"})
				return
			} else {
				_, err := conn.Exec("DELETE FROM sessions WHERE sessionid = ?", sessionId)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/sessions/remove Exec() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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

		masterToken := data["masterkey"].(string)
		if masterToken == secretKey {
			rows, err := conn.Query("SELECT id, username, created FROM users ORDER BY id DESC")
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					c.JSON(200, []map[string]interface{}{})
					return
				} else {
					log.Println("[ERROR] Unknown in /api/listusers query at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-DBQUERY"})
					return
				}
			}
			defer func(rows *sql.Rows) {
				err := rows.Close()
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers row defer at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-ROWCLOSE"})
					return
				}
			}(rows)

			var users []map[string]interface{}
			for rows.Next() {
				var id int
				var username, created string
				if err := rows.Scan(&id, &username, &created); err != nil {
					log.Println("[ERROR] Unknown in /api/listusers row scan at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-ROWSCAN"})
					return
				}
				space, err := getSpace(id)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers getSpace() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-GETSPACE"})
					return
				}
				notes, err := getNoteCount(id)
				if err != nil {
					log.Println("[ERROR] Unknown in /api/listusers getNoteCount() at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
					c.JSON(500, gin.H{"error": "Something went wrong on our end. Please report this bug at https://centrifuge.hectabit.org/hectabit/burgernotes and refer to the documentation for more info. Your error code is: UNKNOWN-API-LISTUSERS-GETNOTECOUNT"})
					return
				}
				users = append(users, map[string]interface{}{"id": id, "username": username, "created": created, "space": space, "notes": notes})
			}
			if err := rows.Err(); err != nil {
				log.Println("[ERROR] Unknown in /api/listusers row iteration at", strconv.FormatInt(time.Now().Unix(), 10)+":", err)
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
