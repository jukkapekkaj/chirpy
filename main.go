package main

import (
	"fmt"
	"net/http"
)

const addr = "localhost:8080"

func main() {

	smux := http.NewServeMux()

	server := http.Server{Handler: smux, Addr: addr}

	fmt.Println("Server listening on", addr)
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}

}
