package main

import (
	"fmt"
	"log"
)

func main() {
	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}
	err1, err2, err3, err4 := store.Init()
	if err1 != nil {
		log.Fatal(err1)
	}
	if err2 != nil {
		log.Fatal(err1)
	}
	if err3 != nil {
		log.Fatal(err3)
	}
	if err4 != nil {
		log.Fatal(err4)
	}
	

	fmt.Printf("%+v\n", store)
	server := NewApiServer(":3000", store)
	server.Run()
}
