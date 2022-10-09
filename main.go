package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/go-logr/logr"
	certv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
}

func main() {
	var metricsAddr string
	var webhookPort int
	var enableLeaderElection bool
	var healthAddr string

	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true, "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&webhookPort, "webhook-port", 0, "Webhook Server port, disabled by default. When enabled, the manager will only work as webhook server, no reconcilers are installed.")
	flag.StringVar(&healthAddr, "health-addr", ":9440", "The address the health endpoint binds to.")

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	kubeconfig := ctrl.GetConfigOrDie()
	kubeclient := kubernetes.NewForConfigOrDie(kubeconfig)

	mgr, err := ctrl.NewManager(kubeconfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               webhookPort,
		LeaderElection:     false,
		// LeaderElectionNamespace: "default",
		// LeaderElectionID:        "5c4b429e.kubernetes.azure.com",
	})

	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to create ready check")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to create health check")
		os.Exit(1)
	}

	err = builder.
		ControllerManagedBy(mgr).
		For(&certv1.CertificateSigningRequest{}).
		Complete(&csrReconciler{Kubeclient: kubeclient, Log: ctrl.Log.WithName("csrcontroller")})
	if err != nil {
		setupLog.Error(err, "could not create controller")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

type csrReconciler struct {
	client.Client
	Kubeclient kubernetes.Interface
	Log        logr.Logger
}

func (r *csrReconciler) InjectClient(c client.Client) error {
	r.Client = c
	return nil
}

func (r *csrReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.Log.Info("got request!")
	var obj certv1.CertificateSigningRequest
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	if shouldSkip(&obj) {
		r.Log.Info("skipping csr")
		return reconcile.Result{}, nil
	}

	if err := r.handle(ctx, &obj); err != nil {
		r.Log.Error(err, "failed to handle request")
		return reconcile.Result{}, err
	}

	r.Log.Info("validated successfully, should approve")
	appendApprovalCondition(&obj, "AutomaticSecureApproval")
	if _, err := r.Kubeclient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, obj.GetName(), &obj, metav1.UpdateOptions{}); err != nil {
		r.Log.Error(err, "failed to patch cert")
		return reconcile.Result{}, err
	}

	r.Log.Info("patched successfully")

	return reconcile.Result{}, nil
}

func appendApprovalCondition(csr *certv1.CertificateSigningRequest, message string) {
	found := false
	for i := range csr.Status.Conditions {
		if csr.Status.Conditions[i].Type == certv1.CertificateApproved {
			found = true
			if csr.Status.Conditions[i].Status != v1.ConditionTrue {

			} else {
				csr.Status.Conditions[i] = certv1.CertificateSigningRequestCondition{
					Type:    certv1.CertificateApproved,
					Reason:  "AutoApproved",
					Message: message,
					Status:  v1.ConditionTrue,
				}
			}
			break
		}
	}
	if !found {
		csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
			Type:    certv1.CertificateApproved,
			Reason:  "AutoApproved",
			Message: message,
			Status:  v1.ConditionTrue,
		})
	}
}

func (r *csrReconciler) handle(ctx context.Context, csr *certv1.CertificateSigningRequest) error {
	req, err := parseCSR(csr.Spec.Request)
	if err != nil {
		return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
	}

	if err := validate(csr, req); err != nil {
		return fmt.Errorf("failed to validate csr: %v", err)
	}

	return nil
}

func shouldSkip(csr *certv1.CertificateSigningRequest) bool {
	if len(csr.Status.Certificate) != 0 {
		return true
	}
	if approved, denied := getCertApprovalCondition(&csr.Status); approved || denied {
		return true
	}
	if certv1.KubeletServingSignerName != csr.Spec.SignerName {
		return true
	}
	return false
}

func getCertApprovalCondition(status *certv1.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certv1.CertificateApproved {
			approved = true
		}
		if c.Type == certv1.CertificateDenied {
			denied = true
		}
	}
	return
}

// Copied from https://github.com/kubernetes/kubernetes/blob/575031b68f5d52e541de6418a59a832252244486/pkg/apis/certificates/helpers.go#L43-L51
// Avoid importing internal k8s deps.
var (
	errOrganizationNotSystemNodesErr = fmt.Errorf("subject organization is not system:nodes")
	errCommonNameNotSystemNode       = fmt.Errorf("subject common name does not begin with 'system:node:'")
	errDnsOrIPSANRequiredErr         = fmt.Errorf("DNS or IP subjectAltName is required")
	errEmailSANNotAllowedErr         = fmt.Errorf("email subjectAltNames are not allowed")
	errUriSANNotAllowedErr           = fmt.Errorf("URI subjectAltNames are not allowed")
)

// Copied from https://github.com/kubernetes/kubernetes/blob/5835544ca568b757a8ecae5c153f317e5736700e/pkg/apis/certificates/v1/helpers.go#L26
// Avoid importing internal k8s repos
// parseCSR decodes a PEM encoded CSR
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func validate(csr *certv1.CertificateSigningRequest, req *x509.CertificateRequest) error {
	// enforce username of client requesting is the node common name
	if csr.Spec.Username != req.Subject.CommonName {
		return fmt.Errorf("csr username %q does not match x509 common name %q", csr.Spec.Username, req.Subject.CommonName)
	}

	if !strings.HasPrefix(req.Subject.CommonName, "system:node:") {
		return errCommonNameNotSystemNode
	}

	if !reflect.DeepEqual([]string{"system:nodes"}, req.Subject.Organization) {
		return errOrganizationNotSystemNodesErr
	}

	// at least one of dnsNames or ipAddresses must be specified
	if len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		return errDnsOrIPSANRequiredErr
	}

	userNameTokens := strings.Split(csr.Spec.Username, ":")
	if len(userNameTokens) != 3 {
		return fmt.Errorf("expected csr username %q to have 2 colons and 3 components, actual %d", csr.Spec.Username, len(userNameTokens))
	}

	nodeName := userNameTokens[2]

	// idk, resolve dns lol?
	// no real source of truth here, ARM for IPs?
	foundHostName := false
	for idx := range req.DNSNames {
		if req.DNSNames[idx] == nodeName {
			foundHostName = true
			break
		}
	}

	if !foundHostName {
		return fmt.Errorf("csr missing node hostname %q as dns name", nodeName)
	}

	if len(req.EmailAddresses) > 0 {
		return errEmailSANNotAllowedErr
	}
	if len(req.URIs) > 0 {
		return errUriSANNotAllowedErr
	}

	if !hasExactUsages(csr) {
		return fmt.Errorf("usages did not match %v", csr.Spec.Usages)
	}

	return nil
}

func hasExactUsages(csr *certv1.CertificateSigningRequest) bool {
	usageMap := kubeletServingRequiredUsages()
	if len(usageMap) != len(csr.Spec.Usages) {
		return false
	}

	for _, u := range csr.Spec.Usages {
		if _, ok := usageMap[u]; !ok {
			return false
		}
	}

	return true
}

func kubeletServingRequiredUsages() map[certv1.KeyUsage]struct{} {
	return map[certv1.KeyUsage]struct{}{
		certv1.UsageDigitalSignature: {},
		certv1.UsageKeyEncipherment:  {},
		certv1.UsageServerAuth:       {},
	}
}
