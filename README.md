# k8s-certmon
k8s-certmon connects to a Kubernetes cluster, looks through all ingress objects with TLS enabled, fetches information about the certificates and expose an API with detailed information about each certificate. It's intended to be used by monitoring systems to alert on expired and invalid certificates.


## Configuration

| Variable                      | Description                                   | Default value |
|-------------------------------|-----------------------------------------------|---------------|
|KUBECONFIG                     | Path to kubeconfig if not running in-cluster  | Null
|LISTEN_PORT                    | Port for webserver                            | 8080          |
|UPDATE_INTERVAL                | Status refresh interval                       | 60            |
|DAYS_LEFT_CRITICAL_THRESHOLD   | Critical threshold for certificate expiration | 3             |
|DAYS_LEFT_WARN_THRESHOLD       | Warning threshold for certificate expiration  | 30            |

## HTTP status codes

The API returns a JSON response with detailed information as well as setting HTTP status codes that reflects current status.

### 200
No certificate errors or warnings found

## 201
Warnings found.
Reasons can be found.

## 202
Critical issues found.