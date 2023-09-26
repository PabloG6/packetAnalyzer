package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/hello", getHello)
	err := http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatal("an error has occurred", err.Error())
		return
	}

	fmt.Println("running server on port :3000")
}

func getHello(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello world \n")
}
