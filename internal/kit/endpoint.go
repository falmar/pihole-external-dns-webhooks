package kit

import "context"

// Endpoint represents a single RPC method. It's a function that takes a request
// and returns a response, along with an error, if any.
type Endpoint func(ctx context.Context, request interface{}) (interface{}, error)
