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
	"net"
	"net/http"
	"os"
	"text/template"
	"time"
	"strings"
)

type EnvVar struct {
	Name, Value string
}
func getEnvVars(prefix string)  []EnvVar {
	// loads all the env variables that start with the prefix given

	envvars := []EnvVar{}
	for  _, env := range os.Environ() {
		if strings.HasPrefix(env, prefix) {
			envvar := strings.SplitN(env,"=",2)
			e := EnvVar{envvar[0],envvar[1]}
			envvars = append(envvars, e)
		}
        }
	return envvars
}

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
	"DidResume": func(conn tls.Conn) string {
		if conn.ConnectionState().DidResume {
			return "true"
		} else {
			return "false"
		}
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
        "LocalAddr": func(req *http.Request) string {
                return req.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
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

func getEnvVarTemplate() *template.Template {
	const temp = `
-- Environment --
{{ range $envvar := . }}{{ $envvar.Name }}: {{ $envvar.Value }}
{{end}}`

	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}

func getTemplate() *template.Template {
	const temp = `
-- Connection --
RemoteAddr: {{.RemoteAddr}}
LocalAddr: {{ . | LocalAddr }}
{{ if .TLS }}
--  TLS  --
ServerName:         {{ .TLS.ServerName }}
Version:            {{ .TLS.Version | TLSVersion }}
NegociatedProtocol: {{ .TLS.NegotiatedProtocol }}
CipherSuite:        {{ .TLS.CipherSuite | CipherSuiteName }} 
DidResume:          {{ .TLS.DidResume }}
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
{{end}}{{end}}`

	t := template.Must(template.New("temp").Funcs(fmap).Parse(temp))
	return t
}
func usageAndExit(error string) {
	fmt.Fprintln(os.Stderr, error)
	flag.Usage()
	os.Exit(-2)
}

type myListener struct {
	net.Listener
	addressHelloMap map[string]*tls.ClientHelloInfo
}

type myConn struct {
	net.Conn
	addressHelloMap map[string]*tls.ClientHelloInfo
}

func (mc myConn) Close() (e error) {
	delete(mc.addressHelloMap, mc.RemoteAddr().String())
	return net.Conn.Close(mc.Conn)
}

func (ml myListener) Accept() (net.Conn, error) {
	c, e := net.Listener.Accept(ml.Listener)
	mc := myConn{
		c,
		ml.addressHelloMap,
	}
	return mc, e
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var keyFile, certFile string
	var envprefix string
	var addr string
	var verbose bool
	var useTLS bool
	var cn string
	var setCookie bool

	flag.StringVar(&keyFile, "key", "", "Certificate key file")
	flag.StringVar(&certFile, "cert", "", "Certificate file")
	flag.StringVar(&addr, "addr", ":8443", "service address")
	flag.BoolVar(&verbose, "verbose", true, "verbose")
	flag.BoolVar(&verbose, "v", true, "verbose")
	flag.BoolVar(&useTLS, "tls", true, "tls")
	flag.StringVar(&cn, "cn", "localhost", "cn of the generated certificate")
	flag.BoolVar(&setCookie, "set-cookie", true, "set cookie")
	flag.StringVar(&envprefix, "env-prefix", "TLSECHO", "environent variables prefix to return")

	flag.Parse()
	if flag.NArg() != 0 {
		usageAndExit("Extra arguments not supported")
	}
	if (keyFile == "") != (certFile == "") {
		usageAndExit("keyfile and certfile set both or none")
	}
	if keyFile != "" && !useTLS {
		usageAndExit("tls disabled and tls credentials set is not supported")
	}
	if keyFile != "" && cn != "" {
		usageAndExit("you can't set cn and certificate files at the same time")
	}

	var addressHelloMap = make(map[string]*tls.ClientHelloInfo)

	helloTemplate := getTLSHelloTemplate()
	httpTemplate := getTemplate()

	envvarsTemplate := getEnvVarTemplate()
	envvars := getEnvVars(envprefix)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if setCookie {
			cookie := &http.Cookie{
				Name:  "cookie",
				Value: "Cookies are delicious delicacies",
			}
			http.SetCookie(w, cookie)
		}
		if useTLS {
			err = helloTemplate.Execute(w, addressHelloMap[r.RemoteAddr])
			if err != nil {
				fmt.Fprintf(w, err.Error(), http.StatusInternalServerError)
				log.Printf(err.Error(), http.StatusInternalServerError)
			}
		}
		if len(envvars) > 0 {
			err= envvarsTemplate.Execute(w, envvars)
			if err != nil {
				fmt.Fprintf(w, err.Error(), http.StatusInternalServerError)
				log.Printf(err.Error(), http.StatusInternalServerError)
			} else if verbose {
				envvarsTemplate.Execute(log.Writer(), envvars)
			}
		}
		err = httpTemplate.Execute(w, r)
		if err != nil {
			fmt.Fprintf(w, err.Error(), http.StatusInternalServerError)
			log.Printf(err.Error(), http.StatusInternalServerError)
		} else if  verbose {
			httpTemplate.Execute(log.Writer(), r)
		}
	})

	if useTLS {
		var certificate tls.Certificate
		var err error
		if keyFile == "" {
			certificate, err = genX509KeyPair(cn)
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
					// with TLS, log the hello info as soon as it arrives, just in case the connection is aborted
					helloTemplate.Execute(log.Writer(), chi)
				}
				return &certificate, nil
			},
		}
		httpServer := &http.Server{
			Addr:      addr,
			TLSConfig: config,
		}
		var ml myListener
		var l net.Listener

		l, err = net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		ml = myListener{
			l,
			addressHelloMap,
		}

		log.Printf("HTTPS server listening on %s", addr)
		log.Fatal(httpServer.ServeTLS(ml, "", ""))
	} else {
		httpServer := &http.Server{
			Addr: addr,
		}
		log.Printf("HTTP server listening on %s", addr)
		log.Fatal(httpServer.ListenAndServe())
	}
}
