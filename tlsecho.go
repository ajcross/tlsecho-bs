package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"text/template"
	"time"
)

func genCertificate(cn string, certPrivKey *rsa.PrivateKey) []byte {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Nanosecond())),
		Subject: pkix.Name{
			Organization:  []string{"San Tome Silver Mine"},
			Country:       []string{"CT"},
			Province:      []string{"Sulaco"},
			Locality:      []string{"Sulaco"},
			StreetAddress: []string{"Street of the Constitution"},
			PostalCode:    []string{"1904"},
			CommonName:    cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		log.Println(err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	return certPEM.Bytes()
}

func genX509KeyPair(cn string) (tls.Certificate, error) {
	var certPEM, keyPEM []byte
	var err error
	var certificate tls.Certificate

	log.Printf("No certificate specified, generating a certificate for cn=%s", cn)
	var key *rsa.PrivateKey
	key, err = rsa.GenerateKey(rand.Reader, 4096)
	certPEM = genCertificate(cn, key)
	keyPEMBuffer := new(bytes.Buffer)
	pem.Encode(keyPEMBuffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyPEM = keyPEMBuffer.Bytes()
	certificate, err = tls.X509KeyPair(certPEM, keyPEM)
	log.Printf("Certificate generated")
	return certificate, err
}

// support functions for templates
var fmap template.FuncMap = template.FuncMap{
	"CipherSuiteName": tls.CipherSuiteName,
	"TLSVersion": func(version uint16) string {
		switch version {
		case tls.VersionTLS10:
			return "TLS1.0"
		case tls.VersionTLS11:
			return "TLS1.1"
		case tls.VersionTLS12:
			return "TLS1.2"
		case tls.VersionTLS13:
			return "TLS1.3"
		case tls.VersionSSL30:
			return "SSL30 Deprecated!!"
		default:
			return fmt.Sprintf("Unknown TLS Version (0x%x)", version)
		}
	},
	"PEM": func(cert x509.Certificate) *bytes.Buffer {
		certPEM := new(bytes.Buffer)
		pem.Encode(certPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		return certPEM
	},
	"KeyUsage": func(keyusage x509.KeyUsage) string {
		var kusage string
		if keyusage&x509.KeyUsageDigitalSignature != 0 {
			kusage += "KeyUsageDigitalSignature "
		}
		if keyusage&x509.KeyUsageContentCommitment != 0 {
			kusage += "KeyUsageContentCommitment "
		}
		if keyusage&x509.KeyUsageKeyEncipherment != 0 {
			kusage += "KeyUsageKeyEncipherment "
		}
		if keyusage&x509.KeyUsageDataEncipherment != 0 {
			kusage += "KeyUsageDataEncipherment "
		}
		if keyusage&x509.KeyUsageKeyAgreement != 0 {
			kusage += "KeyUsageKeyAgreement "
		}
		if keyusage&x509.KeyUsageCertSign != 0 {
			kusage += "KeyUsageCertSign "
		}
		if keyusage&x509.KeyUsageCRLSign != 0 {
			kusage += "KeyUsageCRLSign "
		}
		if keyusage&x509.KeyUsageEncipherOnly != 0 {
			kusage += "KeyUsageEncipherOnly "
		}
		if keyusage&x509.KeyUsageDecipherOnly != 0 {
			kusage += "KeyUsageDecipherOnly "
		}

		return kusage
	},
}

func getTLSHelloTemplate() *template.Template {
	const temp = `
-- TLS hello --
ServerName:        {{ .ServerName }}
SupportedVersions: {{ range .SupportedVersions }} {{ . | TLSVersion }}{{ end }} 
SupportedProtos:   {{ range .SupportedProtos }} {{ . }}{{ end }}
CipherSuites:      {{ range .CipherSuites }} {{ . | CipherSuiteName }}{{ end }}
RemoteAddr:        {{ .Conn.RemoteAddr }}
`
	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}

func getTemplate() *template.Template {
	const temp = `
-- Connection --
RemoteAddr: {{.RemoteAddr}}
{{ if .TLS }}
--  TLS  --
ServerName:         {{ .TLS.ServerName }}
Version:            {{ .TLS.Version | TLSVersion }}
NegociatedProtocol: {{ .TLS.NegotiatedProtocol }}
CipherSuite:        {{.TLS.CipherSuite | CipherSuiteName }} 
{{ range .TLS.PeerCertificates }}
 Subject:      {{ .Subject }}
 Issuer:       {{ .Issuer }}
 SerialNumber: {{ .SerialNumber }}
 NotBefore:    {{ .NotBefore }}
 NotAfter:     {{ .NotAfter }}
 KeyUsage:     {{ .KeyUsage | KeyUsage }}
 PEM:          
{{ . | PEM }}{{ end }}{{ end }}
--  HTTP  --
Proto: {{ .Proto }}
Host: {{ .Host }}
Method: {{ .Method }}
URI: {{ .RequestURI }}
Headers:
{{ range $key, $values := .Header }}{{ range $value := $values }}  {{ $key }}: {{ $value }} 
{{end}}{{end}}
`
	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}
func usageAndExit(error string) {
	fmt.Fprintln(os.Stderr, error)
	flag.Usage()
	os.Exit(-2)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	keyFileFlag := flag.String("key", "", "key file")
	certFileFlag := flag.String("cert", "", "cert file")
	addrFlag := flag.String("addr", ":8443", "service address")
	verboseShortFlag := flag.Bool("verbose", true, "verbose")
	verboseLongFlag := flag.Bool("v", false, "verbose")
	tlsFlag := flag.Bool("tls", true, "tls")
	cnFlag := flag.String("cn", "localhost", "cn of the generated certificate")
	flag.Parse()
	if flag.NArg() != 0 {
		usageAndExit("Extra arguments not supported")
	}
	if (*keyFileFlag == "") != (*certFileFlag == "") {
		usageAndExit("keyfile and certfile must be both specified or none")
	}
	if *keyFileFlag != "" && !*tlsFlag {
		usageAndExit("tls disabled and tls credentials set is not supported")
	}
	verbose := (*verboseShortFlag || *verboseLongFlag)
	useTLS := *tlsFlag
	keyFile := *keyFileFlag
	certFile := *certFileFlag
	addr := *addrFlag

	var addressHelloMap = make(map[string]*tls.ClientHelloInfo)

	helloTemplate := getTLSHelloTemplate()
	httpTemplate := getTemplate()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if useTLS {
			err = helloTemplate.Execute(w, addressHelloMap[r.RemoteAddr])
			if err != nil {
				fmt.Fprintf(w, err.Error(), http.StatusInternalServerError)
				log.Printf(err.Error(), http.StatusInternalServerError)
			}
			delete(addressHelloMap, r.RemoteAddr)
		}
		err = httpTemplate.Execute(w, r)
		if err != nil {
			fmt.Fprintf(w, err.Error(), http.StatusInternalServerError)
			log.Printf(err.Error(), http.StatusInternalServerError)
		}
		if verbose {
			httpTemplate.Execute(log.Writer(), r)
		}
	})

	if useTLS {
		var certificate tls.Certificate
		var err error
		if keyFile == "" {
			certificate, err = genX509KeyPair(*cnFlag)
		} else {
			certificate, err = tls.LoadX509KeyPair(certFile, keyFile)
		}
		if err != nil {
			log.Fatal(err.Error())
		}
		var config *tls.Config

		config = &tls.Config{
			ClientAuth: tls.RequestClientCert,
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				addressHelloMap[chi.Conn.RemoteAddr().String()] = chi
				if verbose {
					helloTemplate.Execute(log.Writer(), chi)
				}
				return &certificate, nil
			},
		}
		httpServer := &http.Server{
			Addr:      addr,
			TLSConfig: config,
		}
		log.Printf("HTTPS server listening on %s", addr)
		log.Fatal(httpServer.ListenAndServeTLS("", ""))
	} else {
		httpServer := &http.Server{
			Addr: addr,
		}
		log.Printf("HTTP server listening on %s", addr)
		log.Fatal(httpServer.ListenAndServe())
	}
}
