FROM golang:1.22.0 AS builder
WORKDIR /go/src/github.com/ca-risken/azure/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/prowler cmd/prowler/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1 AS risken-base

FROM python:3.9.20-alpine3.20
COPY --from=builder /go/bin/prowler /usr/local/prowler/bin/
COPY --from=risken-base /usr/local/bin/env-injector /usr/local/bin/
RUN pip install prowler==4.3.5
ENV DEBUG= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    PROWLER_QUEUE_NAME= \
    PROWLER_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    CORE_SVC_ADDR= \
    DATA_SOURCE_API_SVC_ADDR= \
    ProwlerCommand="prowler" \
    AZURE_CLIENT_ID= \
    AZURE_CLIENT_SECRET= \
    AZURE_TENANT_ID= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/prowler
ENTRYPOINT ["env-injector"]
CMD ["bin/prowler"]
