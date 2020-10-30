FROM golang AS build

WORKDIR /app
COPY . ./

RUN make build

FROM alpine
RUN apk update && apk add --no-cache ca-certificates && update-ca-certificates
COPY --from=build /app/main /app/drone-github-comment
ENTRYPOINT ["/app/drone-github-comment"]

