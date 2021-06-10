package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// Engine drives policy management.
type Engine struct {
	rego rego.PartialResult
}

type EngineConfig struct {
	FileProvider *FileProviderConfig `hcl:"file_provider"`
}

type FileProviderConfig struct {
	PolicyPath      string `hcl:"policy_path"`
	PermissionsPath string `hcl:"permissions_path"`
}

// Input represents context associated with an access request.
type Input struct {
	// Caller is the authenticated identity of the actor making a request.
	Caller string `json:"caller"`

	// FullMethod is the fully-qualified name of the proto rpc service method.
	FullMethod string `json:"full_method"`

	// Req represents data received from the request body. It MUST be a
	// protobuf request object with fields that are serializable as JSON,
	// since they will be used in policy definitions.
	Req interface{} `json:"req"`

	// Admin represents the admin flag on a caller SVID
	Admin bool `json:"admin"`

	// Local represents if it is a local UDS socket call
	Local bool `json:"local"`

	// Downstream represents if caller is from downstream
	Downstream bool `json:"downstream"`

	// Agent represents if caller is an agent
	Agent bool `json:"agent"`
}

type Result struct {
	Allow             bool `json:"allow"`
	Pass              bool `json:"pass"`
	AllowIfAdmin      bool `json:"allow_if_admin"`
	AllowIfLocal      bool `json:"allow_if_local"`
	AllowIfDownstream bool `json:"allow_if_downstream"`
	AllowIfAgent      bool `json:"allow_if_agent"`
}

// NewEngine returns a new policy engine.
func NewEngine(cfg *EngineConfig) (*Engine, error) {
	if cfg == nil || cfg.FileProvider == nil {
		// TODO: return noop engine if config is nil
		return nil, nil
	}
	module, err := ioutil.ReadFile(cfg.FileProvider.PolicyPath)
	if err != nil {
		return nil, err
	}
	storefile, err := os.Open(cfg.FileProvider.PermissionsPath)
	if err != nil {
		return nil, err
	}
	defer storefile.Close()
	store := inmem.NewFromReader(storefile)

	rego := rego.New(
		rego.Query("data.spire.result"),
		rego.Package(`spire`),
		rego.Module("spire.rego", string(module)),
		rego.Store(store),
	)
	pr, err := rego.PartialResult(context.Background())
	if err != nil {
		return nil, err
	}
	return &Engine{
		rego: pr,
	}, nil
}

// Eval determines whether access should be allowed on a resource.
func (e *Engine) Eval(ctx context.Context, input Input) (result Result, err error) {
	rs, err := e.rego.Rego(rego.Input(input)).Eval(ctx)
	if err != nil {
		return result, err
	}

	// TODO(tjulian): figure this out
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return result, errors.New("policy: no matching policies found")
	}

	fmt.Printf("LUMJJB: %+v \n", rs[0])

	b, _ := json.Marshal(input)
	fmt.Printf("INPUT: \n\n%v\n\n", string(b))

	exp := rs[0].Expressions[0]
	resultMap := exp.Value.(map[string]interface{})

	var ok bool
	result.Allow, ok = resultMap["allow"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow\" bool value")
	}

	result.Pass, ok = resultMap["pass"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"pass\" bool value")
	}

	result.AllowIfAdmin, ok = resultMap["allow_if_admin"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_admin\" bool value")
	}

	result.AllowIfLocal, ok = resultMap["allow_if_local"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_local\" bool value")
	}

	result.AllowIfDownstream, ok = resultMap["allow_if_downstream"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_downstream\" bool value")
	}

	result.AllowIfAgent, ok = resultMap["allow_if_agent"].(bool)
	if !ok {
		return result, errors.New("policy: result did not contain \"allow_if_agent\" bool value")
	}

	return result, nil
}
