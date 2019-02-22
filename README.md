**Disclaimer**: This is a POC only. It might have serious security implications. Use on your own risk!

aws-iam-authenticator-auth-proxy for dashboard
==============================================

When provisioning an EKS clusters credentials are short lived. Due to limits on the AWS API a token is only valid for a maximum of 15 minutes.

This tool tries to solve that by enabling transparent auth on an exposed dashboard.

The following requirements have to be fulfilled:

* Use of EKS
* The dashboard is exposed with an nginx-ingress using a configuration that is similar to [dashboard-ingress.yaml.sample]. *Example-Flow: dashboard.k8s.example.com*
* The container is reachable by the nginx ingress controller. *Example-Flow: aws-iam-authenticator-auth-proxy.default.svc.cluster.local*
* A record in this main domain can be created that points to 127.0.0.1 *Example-Flow: auth.dashboard.k8s.example.com*

## Example-Flow

1. User opens https://dashboard.k8s.example.com
1. nginx opens a connection to https://aws-iam-authenticator-auth-proxy.default.svc.cluster.local/validate (where the container is listening)
1. The container checks for the authorisation cookie and will return 401 unauthorized, since the cookie is missing.
1. nginx will redirect to http://auth.dashboard.k8s.example.com:8080/signin?return=https://dashboard.k8s.example.com
1. on the machine of the user the binary will validate the return URL and if it is whitelisted, it will
  * create a valid token using the profile specified in the config file
  * set a cookie for e.g. k8s.example.com with 15min lifetime containing this token
  * redirect to the return URL
1. the browser will again open https://dashboard.k8s.example.com
1. nginx will call https://aws-iam-authenticator-auth-proxy.default.svc.cluster.local/validate again
1. the container will see the cookie and set a Authorization header with the cookie value
1. the user is logged in for 15 min. After 15min the process starts again.

## Getting the client

Run `go get github.com/allcloud-io/aws-iam-authenticator-auth-proxy`

## Client Configuration

Below is the sample configuration file `~/..iam-auth-proxy.yaml` that would match the above flow.

```yaml
ressources:
  example-cluster:                        # cluster-id
    aws-profile: "AWS_PROFILE"            # AWS Profile to use
    cookie-domain: "k8s.example.com"      # the domain to set the cookie on, has to be the common root of both used domains
    cookie-name: "eks-auth"               # (optional) cookie name, if changed has to be changed on the pod, too.
    my-hostname: "auth.k8s.example.com"   # the hostname that this is supposed to be called as, used for validation
    services:                             # a list of whitelisted return URLs (could be multiple dashboards/services in the same EKS domain)
      - http://dashboard.k8s.example.com/
```

## Thanks

This project is based of https://github.com/camptocamp/aws-iam-authenticator-proxy.
