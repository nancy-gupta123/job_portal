package main

import (
	"database/sql"
	"errors"

	"fmt"
	"log"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)




type Storage interface{
	CreateProfile(*Account) error
	CreateLogin(email string) (*Account, error)

	CreateJobApplicant(*JobApplicant)error

	GetUserByEmail(string)(*JobApplicant,error)

	GetCompanyByEmail(string)(*Account,error)

	CreateNewJob(*Job)error

	GetAllJobs()([]Job,error)

	CreateApplicant(*ApplicationRequest)error

	GetApplicationsByJobID(string)([]ApplicationRequest, error)

	GetApplicationsByEmail(string)([]ApplicationRequest, error)


	
}

type PostgresStore struct{
	db *sql.DB
}

func NewPostgresStore()(*PostgresStore,error){
	connstr:="postgresql://postgres:eLORsiMhFormmAIhLPTtrBXzEWOoGDGp@roundhouse.proxy.rlwy.net:53001/railway"

	db,err:=sql.Open("postgres",connstr)
	if err!=nil{
		return nil,err
	}

	
	if err:=db.Ping(); err!=nil{
		log.Fatal("Error pinging database:",err)
		return nil,err
	}
	fmt.Println("Successfully connected to database!")
	return &PostgresStore{
		db:db,
	},nil
}

func (s *PostgresStore) Init() (error,error,error,error) {
	return s.CreateTable(), s.CreateApplicationTable(),s.CreateJob(),s.CreateApplicantTable();
	
}

func (s *PostgresStore)GetApplicationsByEmail(email string) ([]ApplicationRequest, error) {
	if email == "" {
		return nil, errors.New("email cannot be empty")
	}

	query := `SELECT * FROM applicationrequest WHERE applicationEmail = $1`
	rows, err := s.db.Query(query, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var applications []ApplicationRequest
	for rows.Next() {
		var app ApplicationRequest
		if err := rows.Scan(&app.ApplicationNo, &app.ApplicationName, &app.ApplicationEmail, &app.JobId, &app.Time); err != nil {
			return nil, err
		}
		applications = append(applications, app)
	}

	return applications, nil
}


func (s *PostgresStore)GetApplicationsByJobID(jobID string) ([]ApplicationRequest, error) {
	query := `SELECT * FROM applicationrequest WHERE jobId = $1`
	rows, err := s.db.Query(query, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var applications []ApplicationRequest
	for rows.Next() {
		var app ApplicationRequest
		if err := rows.Scan(&app.ApplicationNo, &app.ApplicationName, &app.ApplicationEmail, &app.JobId,&app.Time); err != nil {
			return nil, err
		}
		applications = append(applications, app)
	}
	return applications, nil
}

func(s *PostgresStore)CreateApplicant(acc *ApplicationRequest)error{
	query:=`insert into applicationrequest (applicationName,applicationEmail,jobId,time)values($1,$2,$3,$4)`
	resp,err:=s.db.Query(
		query,
		acc.ApplicationName,
		acc.ApplicationEmail,
		acc.JobId,
		acc.Time,
	)
	if err!=nil{
		return err
	}
	fmt.Printf("%+v",resp)
	return nil
}

func (s *PostgresStore)CreateApplicantTable()error{
	query:=`create table if not exists applicationrequest(
	applicationId serial primary key,
	applicationName varchar(50),
	applicationEmail varchar(50),
	jobId text,
	time timestamp
	)`
	_,err:=s.db.Exec(query)
	if err!=nil{
		fmt.Printf("Error creating account table:%v\n",err)
	}
	return err

}


func (s *PostgresStore) CreateTable()error{
	query:=`create table if not exists account(
	id serial primary key,
	firstName varchar(50),
	lastName varchar(50),
	email varchar(50),
	password Text,
	createdAt timestamp
	)`
	_,err:=s.db.Exec(query)
	if err!=nil{
		fmt.Printf("Error creating account table: %v\n",err)
	}
	return err
}



func (s *PostgresStore)CreateApplicationTable()error{
	//change the query as per new type 
	query:=`create table if not exists applicant(
	id serial primary key,
	userName varchar(50),
	email varchar(100),
	password text,
	resume text not null,
	createdAt timestamp 
	
	)`
	_,err:=s.db.Exec(query)
	if err!=nil{
		fmt.Printf("Error creating account table: %v\n",err)
	}
	return err
}



func (s *PostgresStore)CreateJob()error{
	query:=`create table if not exists job(
	id serial primary key,
	company varchar(50),
	salary varchar(50),
	role varchar(50)
	)`

	_,err:=s.db.Exec(query)
	if err!=nil{
		fmt.Printf("Error creating account table: %v\n",err)
	}
	return err
}

func (s *PostgresStore)CreateProfile(acc *Account)error{

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(acc.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error hashing password: %v", err)
	}
	query:=`insert into account (firstName,lastName,email,password,createdAt)values($1,$2,$3,$4,$5)`

	resp,err:=s.db.Query(
		query,
		acc.FirstName,
		acc.LastName,
		acc.Email,
		string(hashedPassword),
		acc.CreatedAt)
		if err!=nil{
			return err
		}
		fmt.Printf("%+v\n",resp)
		return nil
}

func (s *PostgresStore) CreateJobApplicant(applicant *JobApplicant)error{
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(applicant.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error hashing password: %v", err)
	}
	query:=`insert into applicant (userName,email,password,resume,createdAt)values($1,$2,$3,$4,$5)`
	resp,err:=s.db.Query(
		query,
		applicant.UserName,
		applicant.Email,
		string(hashedPassword),
		applicant.Resume,
		applicant.CreatedAt,
	)
		if err!=nil{
			return err
		}
		fmt.Printf("%+v\n",resp)
		return nil

}

func (s *PostgresStore) GetUserByEmail(email string)(*JobApplicant,error){
	rows,err:=s.db.Query(`select * from applicant where email=$1`,email)
	if err!=nil{
		return nil,err
	}

	
	applicant:=new(JobApplicant)
	log.Println(applicant.Email)
	for rows.Next(){
		err=rows.Scan(&applicant.Id,&applicant.UserName,&applicant.Email,&applicant.Password,&applicant.Resume,&applicant.CreatedAt)
	if err!=nil{
		return nil,err
	}
	}
	
	
	return applicant,nil
}



func (s *PostgresStore)CreateNewJob(job *Job)error{
	query:=`insert into job
	(company,role,salary)values($1,$2,$3)`

	resp,err:=s.db.Query(query,
		job.Company,
		job.Role,
		job.Salary,
	)
	if err!=nil{
		return err
	}
	log.Println(resp)
	return nil

}

func (s *PostgresStore)GetAllJobs()([]Job,error){
	query:=`select id,company,role,salary from job`
	rows,err:=s.db.Query(query)
	if err!=nil{
		return nil,err
	}
	var jobs []Job
	for rows.Next(){
		var job Job
		if err:=rows.Scan(&job.Id,&job.Company,&job.Role,&job.Salary);
		err!=nil{
			return nil,err
		}
		jobs=append(jobs,job)
	}
	if err=rows.Err();err!=nil{
		return nil,err
	}
	return jobs,nil
	
}

func (s *PostgresStore)GetCompanyByEmail(email string)(*Account,error){
	rows,err:=s.db.Query(`select *from account where email=$1`,email)
	if err!=nil{
		return nil,err
	}
	company:=new(Account)
	//err=rows.Scan(&company.Id,&company.FirstName,&company.LastName,&company.Email,&company.Password,&company.CreatedAt)
	
	for rows.Next(){
		err=rows.Scan(&company.Id,&company.FirstName,&company.LastName,&company.Email,&company.Password,&company.CreatedAt)
		if err!=nil{
			return nil,err
		}
	}

	return company,nil
}


func (s *PostgresStore) CreateLogin(email string) (*Account, error) {
	
	row := s.db.QueryRow("SELECT id, firstName, lastName, email, password FROM account WHERE email=$1", email)

	
	var account Account
	err := row.Scan(&account.Id, &account.FirstName, &account.LastName, &account.Email, &account.Password)

	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("account with email [%s] not found", email)
	} else if err != nil {
		return nil, err
	}

	return &account, nil
}

