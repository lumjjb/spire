package middleware

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/pkg/common/policy"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Authorizer interface {
	// Name returns the name of the authorizer. The value may be included in
	// logs and messages returned to callers on authorization failure.
	Name() string

	// AuthorizeCaller is called by the authorization middleware to determine
	// if a caller is authorized. The caller is retrievable on the passed in
	// context. On success, the method returns the (potentially embellished)
	// context passed into the function. On failure, the method returns an
	// error and the returned context is ignored.
	AuthorizeCaller(ctx context.Context, req interface{}) (context.Context, error)
}

// LUMJJB: Add policy here instead,
// LUMJJB check what are possible responses from OPA, maybe can be either OK,
// DENIED OR PASS?
func WithAuthorization(authorizers map[string]Authorizer, policyEngine *policy.Engine, entryFetcher EntryFetcher, agentAuthorizer AgentAuthorizer) middleware.Middleware {
	fmt.Println("LUMJJB: WithAuthorization")
	return &authorizationMiddleware{
		authorizers:     authorizers,
		policyEngine:    policyEngine,
		entryFetcher:    entryFetcher,
		agentAuthorizer: agentAuthorizer,
	}
}

type authorizationMiddleware struct {
	authorizers     map[string]Authorizer
	policyEngine    *policy.Engine
	entryFetcher    EntryFetcher
	agentAuthorizer AgentAuthorizer
}

func (m *authorizationMiddleware) Preprocess(ctx context.Context, methodName string, req interface{}) (context.Context, error) {
	fmt.Println("LUMJJB: authorizationMiddleware.Preprocess")
	ctx, err := callerContextFromContext(ctx)
	if err != nil {
		return nil, err
	}

	fields := make(logrus.Fields)
	if !rpccontext.CallerIsLocal(ctx) {
		fields[telemetry.CallerAddr] = rpccontext.CallerAddr(ctx).String()
	}
	id, ok := rpccontext.CallerID(ctx)
	if ok {
		fields[telemetry.CallerID] = id.String()
	}
	if len(fields) > 0 {
		ctx = rpccontext.WithLogger(ctx, rpccontext.Logger(ctx).WithFields(fields))
	}

	// Check OPA policy and if allow=false and pass=true, go on to regular authz
	// rules
	//allow, pass, err := opaAuth(ctx, m.policyEngine, m.entryFetcher, m.agentAuthorizer, req, methodName)
	allow, pass, err := m.opaAuth2(ctx, req, methodName)
	fmt.Println("LUMJJB: OPA request", id.String(), req, methodName)
	fmt.Println("LUMJJB: OPA policy  results", allow, pass, err)
	if err != nil {
		return nil, err
	}
	if allow {
		return ctx, nil
	} else if !pass {
		return nil, status.Errorf(codes.PermissionDenied, "OPA policy denied without passthrough")
	}

	authorizer, ok := m.authorizers[methodName]
	if !ok {
		middleware.LogMisconfiguration(ctx, "Authorization misconfigured (method not registered); this is a bug")
		return nil, status.Errorf(codes.Internal, "authorization misconfigured for %q (method not registered)", methodName)
	}
	return authorizer.AuthorizeCaller(ctx, req)
}

func (m *authorizationMiddleware) Postprocess(ctx context.Context, methodName string, handlerInvoked bool, rpcErr error) {
	// Intentionally empty.
}
