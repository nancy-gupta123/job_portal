FROM golang:1.24.1-alpine3.20
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod tidy
COPY . .
RUN go build -o job_portal .
RUN chmod +x ./job_portal
EXPOSE 3000
ENTRYPOINT [ "./job_portal" ]