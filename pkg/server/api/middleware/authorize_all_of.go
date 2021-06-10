package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/spiffe/spire/pkg/common/api/middleware"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthorizeAllOf combines authorizers where only if all authorizers succeed,
// then the caller is authorized. Specifically:
// 1. If any authorizer returns any status code other than OK or
// PERMISSION_DENIED, the authorization fails.
// 2. If all authorizers return OK, then authorization succeeds
// succeeds.
// 3. Otherwise, if at least one authorizer returns PERMISSION_DENIED, the
// authorization fails.
func AuthorizeAllOf(authorizers ...Authorizer) Authorizer {
	names := make([]string, 0, len(authorizers))
	for _, authorizer := range authorizers {
		names = append(names, authorizer.Name())
	}

	return allOfAuthorizer{
		names:       names,
		authorizers: authorizers,
	}
}

type allOfAuthorizer struct {
	names       []string
	authorizers []Authorizer
}

func (a allOfAuthorizer) Name() string {
	return fmt.Sprintf("all-of[%s]", strings.Join(a.names, ","))
}

func (a allOfAuthorizer) AuthorizeCaller(ctx context.Context, req interface{}) (context.Context, error) {
	if len(a.authorizers) == 0 {
		middleware.LogMisconfiguration(ctx, "Authorization misconfigured (no authorizers); this is a bug")
		return nil, status.Error(codes.Internal, "authorization misconfigured (no authorizers)")
	}

	for _, authorizer := range a.authorizers {
		nextCtx, err := authorizer.AuthorizeCaller(ctx, req)
		st := status.Convert(err)
		switch st.Code() {
		case codes.OK:
			ctx = nextCtx
		case codes.PermissionDenied:
			return nil, status.Errorf(codes.PermissionDenied, "authorization failed on %q", authorizer.Name())
		default:
			return nil, err
		}
	}

	return ctx, nil
}
