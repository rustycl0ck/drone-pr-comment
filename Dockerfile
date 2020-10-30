FROM golang AS build

WORKDIR /app
COPY . ./

RUN make build

FROM scratch
COPY --from=build /app/main /app/drone-github-comment
ENTRYPOINT ["/app/drone-github-comment"]

