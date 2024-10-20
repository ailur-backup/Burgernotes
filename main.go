package main

import (
	"bytes"
	"git.ailur.dev/ailur/burgernotes/git.ailur.dev/ailur/burgernotes/protobuf"

	"errors"
	"io"
	"os"
	"strings"
	"time"

	"crypto/ed25519"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"

	library "git.ailur.dev/ailur/fg-library/v2"
	nucleusLibrary "git.ailur.dev/ailur/fg-nucleus-library"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var ServiceInformation = library.Service{
	Name: "burgernotes",
	Permissions: library.Permissions{
		Authenticate:              true,  // This service does require authentication
		Database:                  true,  // This service does require database access
		BlobStorage:               true,  // This service does require blob storage access
		InterServiceCommunication: true,  // This service does require inter-service communication
		Resources:                 false, // This service is API-only, so it does not require resources
	},
	ServiceID: uuid.MustParse("b0bee29e-00c4-4ead-a5d6-3f792ff25174"),
}

func unmarshalProtobuf(r *http.Request, protobuf proto.Message) error {
	var protobufData []byte
	_, err := r.Body.Read(protobufData)
	if err != nil {
		return err
	}

	err = proto.Unmarshal(protobufData, protobuf)
	if err != nil {
		return err
	}

	return nil
}

func logFunc(message string, messageType uint64, information library.ServiceInitializationInformation) {
	// Log the message to the logger service
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000002"), // Logger service
		MessageType:  messageType,
		SentAt:       time.Now(),
		Message:      message,
	}
}

func askBlobService(body any, information library.ServiceInitializationInformation, context uint64) (library.InterServiceMessage, error) {
	// Ask the blob storage service for the thing
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000003"), // Blob storage service
		MessageType:  context,
		SentAt:       time.Now(),
		Message:      body,
	}

	// 3 second timeout
	timeoutChan := make(chan struct{})
	go func() {
		time.Sleep(3 * time.Second)
		logFunc("Timeout while waiting for the quota from the blob storage service", 2, information)
		close(timeoutChan)
	}()

	// Wait for the response
	select {
	case response := <-information.Inbox:
		return response, nil
	case <-timeoutChan:
		return library.InterServiceMessage{}, errors.New("timeout")
	}
}

func getQuotaOrUsed(userID uuid.UUID, information library.ServiceInitializationInformation, context uint64) (int64, error) {
	response, err := askBlobService(userID, information, context)
	if err != nil {
		return 0, err
	} else if response.MessageType != 0 {
		return 0, response.Message.(error)
	} else {
		return response.Message.(int64), nil
	}
}

func getQuota(userID uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	return getQuotaOrUsed(userID, information, 3)
}

func getUsed(userID uuid.UUID, information library.ServiceInitializationInformation) (int64, error) {
	return getQuotaOrUsed(userID, information, 4)
}

func deleteNote(userID uuid.UUID, noteID uuid.UUID, information library.ServiceInitializationInformation) error {
	response, err := askBlobService(nucleusLibrary.File{
		User: userID,
		Name: noteID.String(),
	}, information, 2)
	if err != nil {
		return err
	}

	if response.MessageType != 0 {
		return response.Message.(error)
	} else {
		return nil
	}
}

func modifyNote(userID uuid.UUID, noteID uuid.UUID, data []byte, information library.ServiceInitializationInformation) error {
	response, err := askBlobService(nucleusLibrary.File{
		User:  userID,
		Name:  noteID.String(),
		Bytes: data,
	}, information, 0)
	if err != nil {
		return err
	}

	if response.MessageType != 0 {
		return response.Message.(error)
	} else {
		return nil
	}
}

func getNote(userID uuid.UUID, noteID uuid.UUID, information library.ServiceInitializationInformation) (*os.File, error) {
	response, err := askBlobService(nucleusLibrary.File{
		User: userID,
		Name: noteID.String(),
	}, information, 1)
	if err != nil {
		return nil, err
	}

	if response.MessageType != 0 {
		return nil, response.Message.(error)
	} else {
		return response.Message.(*os.File), nil
	}
}

func renderProtobuf(statusCode int, w http.ResponseWriter, protobuf proto.Message, information library.ServiceInitializationInformation) {
	w.WriteHeader(statusCode)
	data, err := proto.Marshal(protobuf)
	if err != nil {
		logFunc(err.Error(), 2, information)
	}
	w.Header().Add("Content-Type", "application/x-protobuf")
	_, err = w.Write(data)
	if err != nil {
		logFunc(err.Error(), 2, information)
	}
}

func verifyJWT(token string, publicKey ed25519.PublicKey) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token")
	}

	// Check if the token expired
	date, err := claims.GetExpirationTime()
	if err != nil || date.Before(time.Now()) || claims["sub"] == nil || claims["isOpenID"] == nil || claims["isOpenID"].(bool) {
		return claims, errors.New("invalid token")
	}

	return claims, nil
}

func getUsername(token string, oauthHostName string, publicKey ed25519.PublicKey) (string, string, error) {
	// Verify the JWT
	_, err := verifyJWT(token, publicKey)
	if err != nil {
		return "", "", err
	}

	// Get the user's information
	var responseData struct {
		Username string `json:"username"`
		Sub      string `json:"sub"`
	}
	request, err := http.NewRequest("GET", oauthHostName+"/api/oauth/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", err
	}

	if response.StatusCode != 200 || response.Body == nil || response.Body == http.NoBody {
		return "", "", errors.New("invalid response")
	}

	err = json.NewDecoder(response.Body).Decode(&responseData)
	if err != nil {
		return "", "", err
	}

	return responseData.Sub, responseData.Username, nil
}

func Main(information library.ServiceInitializationInformation) *chi.Mux {
	var conn library.Database
	hostName := information.Configuration["hostName"].(string)

	// Initiate a connection to the database
	// Call service ID 1 to get the database connection information
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), // Service initialization service
		MessageType:  1,                                                      // Request connection information
		SentAt:       time.Now(),
		Message:      nil,
	}

	// Wait for the response
	response := <-information.Inbox
	if response.MessageType == 2 {
		// This is the connection information
		// Set up the database connection
		conn = response.Message.(library.Database)
		if conn.DBType == library.Sqlite {
			// Create the users table
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BLOB NOT NULL UNIQUE, publicKey BLOB NOT NULL, USERNAME TEXT NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the notes table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS notes (id BLOB NOT NULL UNIQUE, userID BLOB NOT NULL, title BLOB NOT NULL, titleIV BLOB NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		} else {
			// Create the users table
			_, err := conn.DB.Exec("CREATE TABLE IF NOT EXISTS users (id BYTEA NOT NULL UNIQUE, publicKey BYTEA NOT NULL, USERNAME TEXT NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
			// Create the notes table
			_, err = conn.DB.Exec("CREATE TABLE IF NOT EXISTS notes (id BYTEA NOT NULL UNIQUE, userID BYTEA NOT NULL, title BYTEA NOT NULL, titleIV BYTEA NOT NULL)")
			if err != nil {
				logFunc(err.Error(), 3, information)
			}
		}
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Ask the authentication service for the public key
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000004"), // Authentication service
		MessageType:  2,                                                      // Request public key
		SentAt:       time.Now(),
		Message:      nil,
	}

	var publicKey ed25519.PublicKey = nil

	// 3 second timeout
	go func() {
		time.Sleep(3 * time.Second)
		if publicKey == nil {
			logFunc("Timeout while waiting for the public key from the authentication service", 3, information)
		}
	}()

	// Wait for the response
	response = <-information.Inbox
	if response.MessageType == 2 {
		// This is the public key
		publicKey = response.Message.(ed25519.PublicKey)
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Ask the authentication service for the OAuth host name
	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000004"), // Authentication service
		MessageType:  0,                                                      // Request OAuth host name
		SentAt:       time.Now(),
		Message:      nil,
	}

	var oauthHostName string

	// 3 second timeout
	go func() {
		time.Sleep(3 * time.Second)
		if oauthHostName == "" {
			logFunc("Timeout while waiting for the OAuth host name from the authentication service", 3, information)
		}
	}()

	// Wait for the response
	response = <-information.Inbox
	if response.MessageType == 0 {
		// This is the OAuth host name
		oauthHostName = response.Message.(string)
	} else {
		// This is an error message
		// Log the error message to the logger service
		logFunc(response.Message.(error).Error(), 3, information)
	}

	// Ask the authentication service to create a new OAuth2 client
	urlPath, err := url.JoinPath(hostName, "/oauth")
	if err != nil {
		logFunc(err.Error(), 3, information)
	}

	information.Outbox <- library.InterServiceMessage{
		ServiceID:    ServiceInformation.ServiceID,
		ForServiceID: uuid.MustParse("00000000-0000-0000-0000-000000000004"), // Authentication service
		MessageType:  1,                                                      // Create OAuth2 client
		SentAt:       time.Now(),
		Message: nucleusLibrary.OAuthInformation{
			Name:        "Data Tracker",
			RedirectUri: urlPath,
			KeyShareUri: "",
			Scopes:      []string{"openid"},
		},
	}

	oauthResponse := nucleusLibrary.OAuthResponse{}

	// 3 second timeout
	go func() {
		time.Sleep(3 * time.Second)
		if oauthResponse == (nucleusLibrary.OAuthResponse{}) {
			logFunc("Timeout while waiting for the OAuth response from the authentication service", 3, information)
		}
	}()

	// Wait for the response
	response = <-information.Inbox
	switch response.MessageType {
	case 0:
		// Success, set the OAuth response
		oauthResponse = response.Message.(nucleusLibrary.OAuthResponse)
		logFunc("Initialized with App ID: "+oauthResponse.AppID, 0, information)
	case 1:
		// An error which is their fault
		logFunc(response.Message.(error).Error(), 3, information)
	case 2:
		// An error which is our fault
		logFunc(response.Message.(error).Error(), 3, information)
	default:
		// An unknown error
		logFunc("Unknown error", 3, information)
	}

	// Set up the router
	router := chi.NewRouter()

	// Set up the static routes
	staticDir, err := fs.Sub(information.ResourceDir, "static")
	if err != nil {
		logFunc(err.Error(), 3, information)
	} else {
		router.Handle("/bgn-static/*", http.StripPrefix("/bgn-static/", http.FileServerFS(staticDir)))
	}

	// Set up the routes
	router.Post("/api/notes/add", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.Token
		err := unmarshalProtobuf(r, &requestData)

		// Verify the JWT
		claims, err := verifyJWT(requestData.Token, publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Generate a new note UUID
		noteID := uuid.New()

		// Check if the user has reached their quota
		quota, err := getQuota(uuid.MustParse(claims["sub"].(string)), information)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x02}}, information)
			return
		}

		used, err := getUsed(uuid.MustParse(claims["sub"].(string)), information)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x03}}, information)
			return
		}

		if used >= quota {
			renderProtobuf(403, w, &protobuf.Error{Error: "Quota reached"}, information)
			return
		}

		// Try to insert the note into the database
		_, err = conn.DB.Exec("INSERT INTO notes (id, userID) VALUES ($1, $2)", noteID, claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x04}}, information)
		} else {
			noteIdBytes, err := noteID.MarshalBinary()
			if err != nil {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x05}}, information)
			}
			renderProtobuf(200, w, &protobuf.NoteID{NoteId: noteIdBytes}, information)
		}
	})

	router.Post("/api/notes/remove", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.NoteRequest
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		// Verify the JWT
		claims, err := verifyJWT(requestData.Token.String(), publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Try to remove the note from the database
		_, err = conn.DB.Exec("DELETE FROM notes WHERE id = $1 AND userID = $2", requestData.NoteId, claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x06}}, information)
		}

		// If it's there, try to remove the note from the blob storage
		err = deleteNote(uuid.MustParse(claims["sub"].(string)), uuid.Must(uuid.FromBytes(requestData.NoteId.GetNoteId())), information)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x07}}, information)
		}

		w.WriteHeader(200)
	})

	router.Post("/api/notes/list", func(w http.ResponseWriter, r *http.Request) {
		// Verify the JWT
		var requestData protobuf.Token
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		claims, err := verifyJWT(requestData.Token, publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Try to get the notes from the database
		rows, err := conn.DB.Query("SELECT id, title, titleIV FROM notes WHERE userID = $1", claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x08}}, information)
			return
		}

		// Create the notes list
		var notes protobuf.ApiNotesListResponse

		// Iterate through the rows
		for rows.Next() {
			var title, titleIV, noteID []byte
			err = rows.Scan(&noteID, &title, &titleIV)
			if err != nil {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x09}}, information)
				return
			}

			// Append the note to the list
			notes.Notes = append(notes.Notes, &protobuf.NoteMetadata{
				NoteId: &protobuf.NoteID{
					NoteId: noteID,
				},
				Title: &protobuf.AESData{
					Data: title,
					Iv:   titleIV,
				},
			})
		}

		// Render the notes list
		renderProtobuf(200, w, &notes, information)
	})

	router.Post("/api/notes/get", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.NoteRequest
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		// Verify the JWT
		claims, err := verifyJWT(requestData.Token.String(), publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Try to get the note from the database
		var title, titleIV []byte
		err = conn.DB.QueryRow("SELECT title, titleIV FROM notes WHERE id = $1 AND userID = $2", requestData.NoteId, claims["sub"]).Scan(&title, &titleIV)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x0A}}, information)
			return
		}

		// Get the note from the blob storage
		noteFile, err := getNote(uuid.MustParse(claims["sub"].(string)), uuid.Must(uuid.FromBytes(requestData.NoteId.GetNoteId())), information)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x0B}}, information)
			return
		}

		// The IV is the first 16 bytes of the file
		iv := make([]byte, 16)
		_, err = noteFile.Read(iv)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x0C}}, information)
			return
		}

		// The rest of the file is the data
		data, err := io.ReadAll(noteFile)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x0D}}, information)
			return
		}

		// Close the file
		err = noteFile.Close()
		if err != nil {
			logFunc("Resource leak in /api/notes/get", 2, information)
		}

		// Render the note
		renderProtobuf(200, w, &protobuf.Note{
			Note: &protobuf.AESData{
				Data: data,
				Iv:   iv,
			},
			Metadata: &protobuf.NoteMetadata{
				NoteId: requestData.NoteId,
				Title: &protobuf.AESData{
					Data: title,
					Iv:   titleIV,
				},
			},
		}, information)
	})

	router.Post("/api/notes/edit", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.ApiNotesEditRequest
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		// Verify the JWT
		claims, err := verifyJWT(requestData.Token.String(), publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Update the title
		_, err = conn.DB.Exec("UPDATE notes SET title = $1, titleIV = $2 WHERE id = $3 AND userID = $4", requestData.Note.Metadata.Title.Data, requestData.Note.Metadata.Title.Iv, requestData.Note.Metadata.NoteId, claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x0E}}, information)
			return
		}

		// Edit the note in the blob storage
		err = modifyNote(uuid.MustParse(claims["sub"].(string)), uuid.Must(uuid.FromBytes(requestData.Note.Metadata.NoteId.GetNoteId())), bytes.Join([][]byte{requestData.Note.Note.Iv, requestData.Note.Note.Data}, nil), information)
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x0F}}, information)
			return
		}

		w.WriteHeader(200)
	})

	router.Post("/api/notes/purge", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.Token
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		// Verify the JWT
		claims, err := verifyJWT(requestData.Token, publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Get the notes from the database
		rows, err := conn.DB.Query("SELECT id FROM notes WHERE userID = $1", claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x10}}, information)
			return
		}

		// Iterate through the rows
		for rows.Next() {
			var noteID []byte
			err = rows.Scan(&noteID)
			if err != nil {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x11}}, information)
				return
			}

			// Try to remove the note from the blob storage
			err = deleteNote(uuid.MustParse(claims["sub"].(string)), uuid.Must(uuid.FromBytes(noteID)), information)
			if err != nil {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x12}}, information)
				return
			}
		}

		// Remove the notes from the database
		_, err = conn.DB.Exec("DELETE FROM notes WHERE userID = $1", claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x13}}, information)
			return
		}
	})

	router.Post("/api/signup", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.ApiSignupRequest
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		// Verify the JWT
		sub, username, err := getUsername(requestData.Token.String(), oauthHostName, publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Try to insert the user into the database
		_, err = conn.DB.Exec("INSERT INTO users (id, publicKey, username) VALUES ($1, $2, $3)", sub, requestData.PublicKey, username)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				renderProtobuf(409, w, &protobuf.Error{Error: "User already exists"}, information)
			} else {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x01}}, information)
			}
			return
		}

		w.WriteHeader(200)
	})

	router.Post("/api/delete", func(w http.ResponseWriter, r *http.Request) {
		var requestData protobuf.Token
		err := unmarshalProtobuf(r, &requestData)
		if err != nil {
			renderProtobuf(400, w, &protobuf.Error{Error: "Invalid request"}, information)
			return
		}

		// Verify the JWT
		claims, err := verifyJWT(requestData.Token, publicKey)
		if err != nil {
			renderProtobuf(403, w, &protobuf.Error{Error: "Invalid token"}, information)
			return
		}

		// Try to remove the user from the database
		_, err = conn.DB.Exec("DELETE FROM users WHERE id = $1", claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x14}}, information)
			return
		}

		// Get the notes from the database
		rows, err := conn.DB.Query("SELECT id FROM notes WHERE userID = $1", claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x15}}, information)
			return
		}

		// Iterate through the rows
		for rows.Next() {
			var noteID []byte
			err = rows.Scan(&noteID)
			if err != nil {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x16}}, information)
				return
			}

			// Try to remove the note from the blob storage
			err = deleteNote(uuid.MustParse(claims["sub"].(string)), uuid.Must(uuid.FromBytes(noteID)), information)
			if err != nil {
				renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x17}}, information)
				return
			}
		}

		// Remove the notes from the database
		_, err = conn.DB.Exec("DELETE FROM notes WHERE userID = $1", claims["sub"])
		if err != nil {
			renderProtobuf(500, w, &protobuf.ServerError{ErrorCode: []byte{0x18}}, information)
			return
		}

		w.WriteHeader(200)
	})

	// TODO: Implement shared notes

	return router
}
