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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	SecretName  string   `json:"secretName"`
	Namespace   string   `json:"namespace"`
	Issuer      string   `json:"issuer"`
	CommonNames []string `json:"commonNames"`
	NotBefore   string   `json:"notBefore"`
	NotAfter    string   `json:"notAfter"`
	DNSNames    []string `json:"dnsNames"`
	DaysLeft    int      `json:"daysLeft" default:"0"`
	IsValid     bool     `json:"isValid" default:"false"`
}

// StatusResponse holds the data for the JSON status response returned by this API.
type StatusResponse struct {
	LastUpdated  string             `json:"lastUpdated"`
	Errors       []string           `json:"errors"`
	Warnings     []string           `json:"warnings"`
	Certificates []*CertificateInfo `json:"certificates"`
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
func getx509Data(client *kubernetes.Clientset, secret v1.Secret) (*x509.Certificate, error) {

	tlsCrt, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("tls.crt does not exist in %s/%s", secret.Namespace, secret.Name)
	}

	if len(tlsCrt) == 0 {
		return nil, fmt.Errorf("tls.crt for %s/%s is empty", secret.Namespace, secret.Name)
	}

	block, _ := pem.Decode(tlsCrt)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode certificate %s/%s", secret.Namespace, secret.Name)
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate %s/%s", secret.Namespace, secret.Name)
	}

	return parsedCert, nil
}

// Get a list of tls secrets and its certificate data in the cluster.
func getCertificateList(appConfig *ApplicationConfig) (certificateInfoList []*CertificateInfo, warnings []string, errors []string) {
	namespaces, err := appConfig.KubeClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		errors = append(errors, err.Error())
		return nil, warnings, errors
	}

	for _, ns := range namespaces.Items {
		secrets, _ := appConfig.KubeClient.CoreV1().Secrets(ns.Name).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, secret := range secrets.Items {
			if secret.Type != "kubernetes.io/tls" {
				continue
			}

			if originNS, ok := secret.Labels["kubed.appscode.com/origin.namespace"]; ok {
				if originNS != ns.Name {
					continue
				}
			}

			certificateInfo := &CertificateInfo{
				SecretName: secret.Name,
				Namespace:  ns.Name,
			}

			x509Data, err := getx509Data(appConfig.KubeClient, secret)

			if err != nil {
				errors = append(errors, err.Error())
				continue
			} else {
				daysLeft := (x509Data.NotAfter.Unix() - time.Now().Unix()) / 86400

				certificateInfo.NotBefore = x509Data.NotBefore.String()
				certificateInfo.NotAfter = x509Data.NotAfter.String()
				certificateInfo.Issuer = x509Data.Issuer.CommonName
				certificateInfo.DNSNames = x509Data.DNSNames
				certificateInfo.DaysLeft = int(daysLeft)
				certificateInfo.IsValid = true

				for _, n := range x509Data.Subject.Names {
					certificateInfo.CommonNames = append(certificateInfo.CommonNames, fmt.Sprintf("%v", n.Value))
				}

				if daysLeft <= 0 {
					errors = append(errors, fmt.Sprintf("certificate %s/%s (%s) expired on %s", ns.Name, certificateInfo.SecretName, strings.Join(certificateInfo.DNSNames, ", "), certificateInfo.NotAfter))
					certificateInfo.IsValid = false
				} else if daysLeft <= int64(appConfig.CritDaysLeft) {
					errors = append(errors, fmt.Sprintf("certificate %s/%s (%s) will expire in %d days (%s).", ns.Name, certificateInfo.SecretName, strings.Join(certificateInfo.DNSNames, ", "), certificateInfo.DaysLeft, certificateInfo.NotAfter))
				} else if daysLeft < int64(appConfig.WarnDaysLeft) {
					warnings = append(warnings, fmt.Sprintf("certificate %s/%s (%s) will expire in %d days (%s).", ns.Name, certificateInfo.SecretName, strings.Join(certificateInfo.DNSNames, ", "), certificateInfo.DaysLeft, certificateInfo.NotAfter))
				}
			}

			certificateInfoList = append(certificateInfoList, certificateInfo)
		}
	}

	if warnings == nil {
		warnings = make([]string, 0)
	}

	if errors == nil {
		errors = make([]string, 0)
	}

	return certificateInfoList, warnings, errors
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

			log.Printf("Fetching secrets with certificate data.\n")
			certList, warnings, errors := getCertificateList(&appConfig)
			currentStatus = StatusResponse{
				LastUpdated:  time.Now().String(),
				Errors:       errors,
				Warnings:     warnings,
				Certificates: certList,
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

			log.Printf("Fetched %d tls secrets in %d seconds.\n\n", len(certList), stop-start)
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
