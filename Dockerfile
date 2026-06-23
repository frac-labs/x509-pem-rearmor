FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o /out/x509-pem-rearmor ./

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/x509-pem-rearmor /x509-pem-rearmor
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/x509-pem-rearmor"]
