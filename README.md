# supreme-goggles

This project aims to provide a Kubernetes controller to automate approval of signing requests for Kubelet serving certificates.

For why you'd want this, see documentation here:
- https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#client-and-serving-certificates
- https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/#sign-the-certificate-signing-request
- https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#approval-rejection-api-client

Client certificates for kubelet have a fully automated controller, but serving certs do not.

## Running

This requires kubelet to run with `--rotate-server-certificates=true`, (currently not set on AKS, for example).

Setting this and restarting kubelet is relatively non disruptive -- you can even delete the serving cert entirely with minimal disruption. Test this in your environment before relying on it in production!

Currently there's only a basic binary build and no container image or Kubernetes manifests. If you've done this thing before, feel free to send a pull request.

There are also no tests. We could use some!

We currently use bazel for builds. 

Simple build
```sh
bazel build supreme-goggles
```

Update dependencies after development
```sh
go mod tidy
bazel run gazelle # generate build files
bazel run gazelle-update-repos # generate repository rules for go deps
bazel run gazelle # regenerate build files due to any repository rule changes
```

Running the operator is as simple as having a kubeconfig defined locally
```sh
bazel run supreme-goggles # run via bazel
# or build and execute directly
bazel build supreme-goggles
./bazel-bin/supreme-goggles_/supreme-goggles
## Requirements

Copied largely from [here](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/#client-and-serving-certificates).

A deployment-specific approval process for kubelet serving certificates should typically only approve CSRs which:
- are requested by nodes (ensure the spec.username field is of the form system:node:<nodeName> and spec.groups contains system:nodes)
- request usages for a serving certificate (ensure spec.usages contains server auth, optionally contains digital signature and key encipherment, and contains no other usages)
- only have IP and DNS subjectAltNames that belong to the requesting node, and have no URI and Email subjectAltNames (parse the x509 Certificate Signing Request in spec.request to verify subjectAltNames)

A method of Client TLS bootstrapping which secures client credentials to each node will suffice to prove these points, which 
is out of scope here but useful.

## Process

- Kubelet uses a bootstrap token to create a CSR for client TLS certificates.
- KCM sees the signer name of the CSR is for Kubelet client cert, validates CSR properties accordingly.
- KCM approves cert. 
  - https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/certificates/approver/sarapprove.go
  - sar approver uses subject access review against username of csr spec, which will be allowed for bootstrap tokens by built in rbac policies.
- KCM signs approved cert (separate approver and signer controllers).
  - https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/certificates/signer/signer.go
- Kubelet sees approved cert, requests and receives it. Bootstrap token has GET/LIST CSR 
  - (actually on all CSR, that is an issue, it can read other nodes CSR even with NodeRestriction because NodeRestriction uses system:nodes and doesn't limit CSR for bootstrapping? from Ace's glance at source code)
  - https://github.com/kubernetes/kubernetes/issues/54079 - RBAC for single object
  - https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go
  - https://github.com/kubernetes/kubernetes/blob/master/pkg/auth/nodeidentifier/default.go#L37 - uses system:nodes prefix
  - https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/auth/authorizer/node/node_authorizer.go - no certs filtered here
  - https://github.com/kubernetes/kubernetes/blob/master/plugin/pkg/auth/authenticator/token/bootstrap/bootstrap.go#L147 bootstrap token does get authorized by name, but system-bootstrappers
  - Vanilla k8s has no way to ensure the node name of the holder of the bootstrap token matches the CSR. This can be implemented in cloud provider/host specific ways. For example, Azure offers attested VM metadata. 
  - Approval for the client CSR depends on the attested host name (submitted by client) of the requesting bootstrap token matching the requested subject for the hostname
    - In Azure this will require taking the attested data, validating and decoding the VmId, requesting the bootstrap token from a custom server which will look up the VM against ARM, ensuring both its globally unique VMID matches (since resource IDs can be recreated/squatted) and the hostname matches the client request.
  - Limiting GET/LIST CSRs to individual CSRs per bootstrap token is possible, but requires either extremely fine grained, high churn RBAC rules, or a webhook on CSRs. 
- Kubelet uses the new certs, creates a new CSR
  - https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/certificate/kubelet.go for implementation.
  - pkg/registry/certificates/certificates/strategy.go for apiserver setting of username to node username, reliably
  - Signer appears to do some basic validation for kubelet serving certs, but does not validate username of CSR is node client cert https://cs.github.com/kubernetes/kubernetes/blob/575031b68f5d52e541de6418a59a832252244486/pkg/controller/certificates/signer/signer.go#L251
- Custom approver sees new CSR for signer name
  - If approved or failed, exit early
  - If wrong signer, exit early
  - Otherwise mostly follow upstream requirements: https://cs.github.com/kubernetes/kubernetes/blob/575031b68f5d52e541de6418a59a832252244486/pkg/apis/certificates/helpers.go#L68
  - spec.username field is of the form system:node:<nodeName> where <nodeName> is the SAN of the serving cert in the embedded request.
  - Additional validation could involve DNS lookups, similar to https://github.com/postfinance/kubelet-csr-approver/blob/481f790fad7a60dff4089f59604893fcd44af580/internal/controller/regex_ip_checks.go#L20
- KCM signer signs approved cert, kubelet receives cert, life goes on
- Enabling NodeRestriction admission controller ties this all together for higher level resources.

From this point on:
- client and server certificates rotate automatically, as long as kubelet still has a valid client cert.
- if the client cert expires, kubelet falls back to bootstrap credentials. 
- if kubelet's bootstrap credentials use an exec plugin to request a platform auth token and use that to request a short lived bootstrap token, it will be able to re-bootstrap successfully even after client cert expiry with strong guarantees.

The e2e flow guarantees:
- client CSR only receive approval when requested by a bootstrap token with matching hostname, or theselves.
- server CSR only receive approval when requested by a cert matching the requested certificate
- kubelet credentials can never expire in a meaningful way while the control plane is up.

Note there is a built-in RBAC role for the kubelet-serving approver, even though the approver itself is not built-in (only the signer): system:certificates.k8s.io:kubelet-serving-approver
