FROM golang:1.19 as builder

WORKDIR /workspace
COPY go.mod .
COPY go.sum .
COPY main.go .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go

FROM gcr.io/distroless/static:latest
WORKDIR /
COPY --from=builder /workspace/manager .
ENTRYPOINT ["/manager"]
