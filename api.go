package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type ApiServer struct {
	listenAddr string
	store      Storage
}

func NewApiServer(listenAddr string, store Storage) *ApiServer {
	return &ApiServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *ApiServer) Run() {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	router := mux.NewRouter()
	router.HandleFunc("/register", makeHTTPHandlerFunc(s.handleRegister))
	router.HandleFunc("/login", makeHTTPHandlerFunc(s.handlelogin))
	//task for today make api to register as a job applicant
	router.HandleFunc("/job_applicant", makeHTTPHandlerFunc(s.jobApplicant))
	router.HandleFunc("/loginJobApplicant", makeHTTPHandlerFunc(s.loginJobApplicant))
	router.HandleFunc("/jobs", makeHTTPHandlerFunc(s.createJob))
	router.HandleFunc("/getAllJob", makeHTTPHandlerFunc(s.getAllJob))
	router.HandleFunc("/applyJob/{id}", makeHTTPHandlerFunc(s.handleApply))
	router.HandleFunc("/getallApplication/{id}", makeHTTPHandlerFunc(s.handlegetallApplication))
	router.HandleFunc("/getMyApplication", makeHTTPHandlerFunc(s.getMyApplication))
	//give hashing in this api as well
	log.Println("JSON Api Running on port:", s.listenAddr)

	handler := c.Handler(router)
	http.ListenAndServe(s.listenAddr, handler)

}

func makeHTTPHandlerFunc(fn func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (s *ApiServer) handlegetallApplication(w http.ResponseWriter, r *http.Request) error {

	if r.Method != http.MethodGet {
		return fmt.Errorf("method not allowed: %s", r.Method)
	}

	vars := mux.Vars(r)
	jobID := vars["id"]

	if _, err := strconv.Atoi(jobID); err != nil {
		http.Error(w, "Invalid job ID", http.StatusBadRequest)
		return err
	}

	applications, err := s.store.GetApplicationsByJobID(jobID)
	if err != nil {
		return fmt.Errorf("failed to fetch applications: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(applications); err != nil {
		return fmt.Errorf("failed to encode response: %v", err)
	}

	return nil
}
func (s *ApiServer) getMyApplication(w http.ResponseWriter, r *http.Request) error {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing Authorization token", http.StatusUnauthorized)
		return nil
	}

	
	email, err := validate(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return nil
	}

	
	applications, err := s.store.GetApplicationsByEmail(email)
	if err != nil {
		http.Error(w, "Failed to fetch applications", http.StatusInternalServerError)
		return nil
	}

	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(applications)
	return nil
}

func (s *ApiServer) createJob(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
		return nil
	}

	createJobreq := new(CreateJob)
	if err := json.NewDecoder(r.Body).Decode(createJobreq); err != nil {
		return err
	}

	// Validate token and extract email
	email, err := validate(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return nil
	}
	company, err := s.store.GetCompanyByEmail(email)
	if err != nil {
		return err
	}
	log.Println(company)

	job, err := NewJob(company.FirstName, createJobreq.Role, createJobreq.Salary)
	if err != nil {
		return nil

	}
	err = s.store.CreateNewJob(job)

	// Respond with extracted email
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(job)

	return nil

}

func (s *ApiServer) handleRegister(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}

	createAccountReq := new(CreateAccountRequest)
	err := json.NewDecoder(r.Body).Decode(&createAccountReq)
	if err != nil {
		return err
	}

	account, err := NewAccount(createAccountReq.FirstName, createAccountReq.LastName, createAccountReq.Email, createAccountReq.Password)
	if err != nil {
		return err
	}
	err = s.store.CreateProfile(account)
	if err != nil {
		return err
	}

	return json.NewEncoder(w).Encode(account)

}

func (s *ApiServer) jobApplicant(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil
	}

	createAccRequest := new(CreateApplicantRequest)
	if err := json.NewDecoder(r.Body).Decode(createAccRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return nil
	}

	applicant, err := NewApplicant(createAccRequest.UserName, createAccRequest.Email, createAccRequest.Password, createAccRequest.Resume)
	if err != nil {
		http.Error(w, "Failed to create applicant", http.StatusInternalServerError)
		return nil
	}

	existingApplicant, err := s.store.GetUserByEmail(applicant.Email)
	log.Println(existingApplicant.Email)

	if existingApplicant.Email != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		return fmt.Errorf("User already exist")
	}

	if err := s.store.CreateJobApplicant(applicant); err != nil {
		http.Error(w, "Failed to save applicant", http.StatusInternalServerError)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(applicant)
}

func (s *ApiServer) handleApply(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return fmt.Errorf("method not allowed: %s", r.Method)
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
		return nil
	}

	email, err := validate(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return nil
	}

	company, err := s.store.GetUserByEmail(email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return nil
	}

	vars := mux.Vars(r)
	jobID, exists := vars["id"]
	if !exists {
		http.Error(w, "Job ID is required", http.StatusBadRequest)
		return nil
	}

	application, err := NewApplication(company.UserName, email, jobID)
	if err != nil {
		http.Error(w, "Failed to create application", http.StatusInternalServerError)
		return nil
	}

	err = s.store.CreateApplicant(application)
	if err != nil {
		http.Error(w, "Failed to save application", http.StatusInternalServerError)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(application)
	return nil
}

func (s *ApiServer) loginJobApplicant(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}

	req := new(LoginRequest)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	user, err := s.store.GetUserByEmail(req.Email)
	if err != nil {
		return err
	}
	log.Println(user.Password)

	if !user.validPassword1((req.Password)) {
		return fmt.Errorf("not authenticated")

	}
	token, err := createJWT1(user)
	if err != nil {
		return err
	}
	resp := LoginResponse{
		Token: token,
		Email: user.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	return nil
}
func (s *ApiServer) getAllJob(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return fmt.Errorf("method not allowed %s", r.Method)

	}
	jobs, err := s.store.GetAllJobs()
	if err != nil {
		http.Error(w, "Failed to fetch jobs", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(jobs); err != nil {
		http.Error(w, "Error encodeing JSON", http.StatusInternalServerError)
		return err
	}

	return nil

}

func (s *ApiServer) handlelogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	acc, err := s.store.CreateLogin(req.Email)
	if err != nil {
		return err
	}

	if !acc.validPassword((req.Password)) {
		return fmt.Errorf("not authenticated")

	}

	token, err := createJWT(acc)
	if err != nil {
		return err
	}

	resp := LoginResponse{
		Token: token,
		Email: acc.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	fmt.Printf("User logged in: %+v\n", acc)
	return nil

}

var secret = os.Getenv("JWT_SECRET")

func createJWT(account *Account) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt": jwt.NewNumericDate(time.Now().Local().Add(time.Minute * 15)),
		"email":     account.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
func createJWT1(account *JobApplicant) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt": jwt.NewNumericDate(time.Now().Local().Add(time.Minute * 15)),
		"email":     account.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
func createJWT2(account *ApplicationRequest) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt": jwt.NewNumericDate(time.Now().Local().Add(time.Minute * 15)),
		"email":     account.ApplicationEmail,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func validate(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil

	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["email"].(string), nil
	}

	return "", fmt.Errorf("invalid token")
}
