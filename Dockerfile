FROM golang:1.11 as builder
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

RUN mkdir -p /go/src/github.com/allcloud-io/aws-iam-auth-proxy
WORKDIR /go/src/github.com/allcloud-io/aws-iam-authenticator-auth-proxy

COPY Gopkg.lock Gopkg.toml /go/src/github.com/allcloud-io/aws-iam-authenticator-auth-proxy/
RUN dep ensure -vendor-only
# RUN go get -d -u \
#   github.com/Sirupsen/logrus \
#   github.com/kubernetes-sigs/aws-iam-authenticator/pkg/token \
#   github.com/fatih/color \
#   github.com/mitchellh/go-homedir \
#   github.com/spf13/viper
COPY main.go .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags "-linkmode external -extldflags -static" -o /aws-iam-authenticator


FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /aws-iam-authenticator /aws-iam-authenticator
ENTRYPOINT ["/aws-iam-authenticator"]
