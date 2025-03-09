package main

import ("time"
        "golang.org/x/crypto/bcrypt")

type Account struct {
	Id        int `json:"id"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
	Email     string    `json:"email"`
	Password  string     `json:"password"`
	CreatedAt time.Time `json:"createdAt"`
}

type LoginRequest struct{
	Email string `json:"email"`
	Password string `json:"password"`
	
}
type LoginResponse struct{
	Token string `json:"token"`
	Email string `json:"email"`
}


type CreateAccountRequest struct{
	FirstName string `json:"firstName"`
	LastName string `json:"lastName"`
	Email string `json:"Email"`
	Password string `json:"password"`
}

type JobApplicant struct{
	Id int `json:"id"`
	UserName string `json:"userName"`
	Email string `json:"email"`
	Password string `json:"password"`
	Resume  string `json:"resume"`
	CreatedAt time.Time `json:createdAt"`
}

type CreateApplicantRequest struct{
	UserName string `json:"userName"`
	Email string `json:"email"`
	Password string `json:"password"`
	Resume string `json:"resume"`
}

type ApplicationRequest struct{
	ApplicationNo int `json:"applicationNo"`
	ApplicationName string `json:"applicationName"`
	ApplicationEmail string `json:"applicationEmail"`
	JobId string `json:"jobId"`
	Time time.Time `json:"time"`
}

type CreateApplicationRequest struct{
	ApplicationName string `json:"applicationName"`
	ApplicationEmail string `json:"applictionEmail"`
	JobId string `json:"jobId"`
}

func NewApplication(applicationName,applictionEmail string,jobId string)(*ApplicationRequest,error){
	loc, _ := time.LoadLocation("Asia/Kolkata")
	return &ApplicationRequest{
		ApplicationName:applicationName,
		ApplicationEmail:applictionEmail,
		JobId:jobId,
		Time: time.Now().In(loc),
	},nil
}



type Job struct{
	Id int `json:"id"`
	Company string `json:"company"`
	Salary string `json:"salary"`
	Role string `json:"role"`
}

type CreateJob struct{
	Salary string `json:"salary"`
	Role string `json:"role"`
}

func NewApplicant(userName,email,password,resume string)(*JobApplicant,error){
	loc, _ := time.LoadLocation("Asia/Kolkata")
	return &JobApplicant{
		UserName: userName,
		Email: email,
		Password: password,
		Resume: resume,
		CreatedAt: time.Now().In(loc),
	},nil
}
func NewJob(company,role ,salary string)(*Job,error){
	return &Job{
		Company: company,
		Role:role,
		Salary: salary,
	},nil
}






func NewAccount(firstName,lastName,email,password string)(*Account,error){

	loc, _ := time.LoadLocation("Asia/Kolkata")
	return &Account{
	FirstName:firstName,
	LastName:lastName,
	Email:email,
	Password:password,
	CreatedAt:time.Now().In(loc),

	},nil

}

func (acc *Account) validPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(password))
	return err == nil
}
func (acc *JobApplicant) validPassword1(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(acc.Password), []byte(password))
	return err == nil
}

