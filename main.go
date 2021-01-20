package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ApplicationConfig Runtime configuration.
type ApplicationConfig struct {
	KubeConfig     string `envconfig:"KUBECONFIG" default:""`
	UpdateInterval int    `envconfig:"UPDATE_INTERVAL" default:"60"`
	ListenPort     int    `envconfig:"LISTEN_PORT" default:"8080"`
	CritDaysLeft   int    `envconfig:"DAYS_LEFT_CRITICAL_THRESHOLD" default:"3"`
	WarnDaysLeft   int    `envconfig:"DAYS_LEFT_WARN_THRESHOLD" default:"30"`
	KubeClient     *kubernetes.Clientset
}

// CertificateInfo holds information about a certificate.
type CertificateInfo struct {
	Issuer      string   `json:"issuer"`
	CommonNames []string `json:"commonNames"`
	NotBefore   string   `json:"notBefore"`
	NotAfter    string   `json:"notAfter"`
	DNSNames    []string `json:"dnsNames"`
	DaysLeft    int      `json:"daysLeft" default:"0"`
	IsValid     bool     `json:"isValid" default:"false"`
}

// IngressInfo holds information about a ingress.
type IngressInfo struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Hosts           []string          `json:"hosts"`
	TLSSecretName   string            `json:"tlsSecretName"`
	x509            *x509.Certificate `json:"-"`
	CertificateInfo *CertificateInfo  `json:"certificate"`
}

// StatusResponse holds the data for the JSON status response returned by this API.
type StatusResponse struct {
	LastUpdated  string         `json:"lastUpdated"`
	Errors       []string       `json:"errors"`
	Warnings     []string       `json:"warnings"`
	Certificates []*IngressInfo `json:"certificates"`
}

func newKubernetesClient(appConfig *ApplicationConfig) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	if appConfig.KubeConfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", appConfig.KubeConfig)
		if err != nil {
			return nil, err
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

// Parse a kubernetes secret as a PEM certificate and extract information.
// Returns a x509.Certificate object.
func getx509Data(client *kubernetes.Clientset, ingress *IngressInfo) (*x509.Certificate, error) {
	secret, err := client.CoreV1().Secrets(ingress.Namespace).Get(context.Background(), ingress.TLSSecretName, v1.GetOptions{})
	if err != nil {
		return nil, err
	}

	tlsCrt, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("tls.crt does not exist in %s/%s", ingress.Namespace, ingress.TLSSecretName)
	}

	if len(tlsCrt) == 0 {
		return nil, fmt.Errorf("tls.crt for %s/%s is empty", ingress.Namespace, ingress.TLSSecretName)
	}

	block, _ := pem.Decode(tlsCrt)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode certificate %s/%s", ingress.Namespace, ingress.TLSSecretName)
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate %s/%s", ingress.Namespace, ingress.TLSSecretName)
	}

	return parsedCert, nil
}

// Get a list of ingress objects and certificate data in the cluster.
func getIngresses(appConfig *ApplicationConfig) (ingressInfoList []*IngressInfo, warnings []string, errors []string) {
	namespaces, err := appConfig.KubeClient.CoreV1().Namespaces().List(context.Background(), v1.ListOptions{})
	if err != nil {
		errors = append(errors, err.Error())
		return nil, warnings, errors
	}

	for _, ns := range namespaces.Items {
		ingresses, _ := appConfig.KubeClient.ExtensionsV1beta1().Ingresses(ns.Name).List(context.Background(), v1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ingress := range ingresses.Items {
			tls := ingress.Spec.TLS
			for _, tlsSpec := range tls {
				ingressInfo := &IngressInfo{
					Name:          ingress.Name,
					Namespace:     ns.Name,
					TLSSecretName: tlsSpec.SecretName,
					Hosts:         tlsSpec.Hosts,
					x509:          nil,
				}

				x509Data, err := getx509Data(appConfig.KubeClient, ingressInfo)

				if err != nil {
					errors = append(errors, err.Error())
					continue
				} else {
					ingressInfo.x509 = x509Data
					daysLeft := (x509Data.NotAfter.Unix() - time.Now().Unix()) / 86400

					certInfo := &CertificateInfo{
						NotBefore: x509Data.NotBefore.String(),
						NotAfter:  x509Data.NotAfter.String(),
						Issuer:    x509Data.Issuer.CommonName,
						DNSNames:  x509Data.DNSNames,
						DaysLeft:  int(daysLeft),
						IsValid:   true,
					}

					for _, n := range x509Data.Subject.Names {
						certInfo.CommonNames = append(certInfo.CommonNames, fmt.Sprintf("%v", n.Value))
					}

					if daysLeft <= 0 {
						errors = append(errors, fmt.Sprintf("certificate %s/%s (%s) expired on %s", ns.Name, ingress.Name, strings.Join(certInfo.DNSNames, ", "), certInfo.NotAfter))
						certInfo.IsValid = false
					} else if daysLeft <= int64(appConfig.CritDaysLeft) {
						errors = append(errors, fmt.Sprintf("certificate %s/%s (%s) will expire in %d days (%s).", ns.Name, ingress.Name, strings.Join(certInfo.DNSNames, ", "), certInfo.DaysLeft, certInfo.NotAfter))
					} else if daysLeft < int64(appConfig.WarnDaysLeft) {
						warnings = append(warnings, fmt.Sprintf("certificate %s/%s (%s) will expire in %d days (%s).", ns.Name, ingress.Name, strings.Join(certInfo.DNSNames, ", "), certInfo.DaysLeft, certInfo.NotAfter))
					}

					for _, h := range tlsSpec.Hosts {
						if x509Data.VerifyHostname(h) != nil {
							errors = append(errors, fmt.Sprintf("certificate for %s/%s is not valid for host %s", ns.Name, ingress.Name, h))
							certInfo.IsValid = false
						}
					}

					ingressInfo.CertificateInfo = certInfo
				}

				ingressInfoList = append(ingressInfoList, ingressInfo)
			}
		}
	}

	return ingressInfoList, warnings, errors
}

func main() {
	var appConfig ApplicationConfig
	err := envconfig.Process("", &appConfig)

	if err != nil {
		fmt.Printf("Error parsing config: %v\n", err)
		envconfig.Usage("", appConfig)
		os.Exit(1)
	}

	kubeClient, err := newKubernetesClient(&appConfig)
	if err != nil {
		log.Fatalf("Error connecting to kubernetes: %v\n", err.Error())
	}
	appConfig.KubeClient = kubeClient

	var currentStatus StatusResponse

	go func() {
		for {
			start := time.Now().Unix()

			log.Printf("Fetching ingress and certificate data.\n")
			ingressList, warnings, errors := getIngresses(&appConfig)
			currentStatus = StatusResponse{
				LastUpdated:  time.Now().String(),
				Errors:       errors,
				Warnings:     warnings,
				Certificates: ingressList,
			}

			if len(errors) > 0 {
				for _, err := range errors {
					log.Printf("Error: %s\n", err)
				}
			}

			if len(warnings) > 0 {
				for _, warn := range warnings {
					log.Printf("Warning: %s\n", warn)
				}
			}

			stop := time.Now().Unix()

			log.Printf("Fetched %d ingress objects in %d seconds.\n\n", len(ingressList), stop-start)
			time.Sleep(time.Duration(appConfig.UpdateInterval) * time.Second)
		}
	}()

	log.Printf("Starting server on port %d\n", appConfig.ListenPort)

	err = http.ListenAndServe(fmt.Sprintf(":%d", appConfig.ListenPort), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		if len(currentStatus.Errors) > 0 {
			w.WriteHeader(202)
		} else if len(currentStatus.Warnings) > 0 {
			w.WriteHeader(201)
		} else {
			w.WriteHeader(200)
		}

		j, err := json.MarshalIndent(currentStatus, "", "  ")
		if err != nil {
			w.Write([]byte(fmt.Sprintf("{\"error\": \"%s\"}\n", err.Error())))
			return
		}

		w.Write(j)
	}))

	if err != nil {
		log.Fatalf("Failed to start webserver on port %d: %s\n", appConfig.ListenPort, err.Error())
	}
}
