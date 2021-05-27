FROM golang:alpine3.13 as builder

RUN mkdir -p /build
WORKDIR /build

COPY . .
COPY go.mod .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o k8s-certmon .

FROM scratch
COPY --from=builder /build/k8s-certmon /
ENTRYPOINT [ "/k8s-certmon" ]
