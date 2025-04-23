FROM golang:1.23.4-alpine AS build

WORKDIR /app

# Copy the Go module files
COPY go.mod .
#COPY go.sum .

# Download the Go module dependencies
RUN go mod download

COPY . .

RUN go build -o /myapp .

FROM docker.io/chromedp/headless-shell:137.0.7106.2 AS run

# chromedp/headless-shell is based on debian:bullseye-slim, which does not have ca-certificates installed by default.
RUN apt-get update && apt install ca-certificates -y

# Copy the application executable from the build image
COPY --from=build /myapp /myapp

WORKDIR /app
# Create tokens directory with proper permissions
RUN mkdir -p /app/tokens && chmod 750 /app/tokens

EXPOSE 443
VOLUME ["/app/tokens"]
ENTRYPOINT [ "/myapp"]
CMD ["server"]