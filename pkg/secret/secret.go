// Package secret holds the ADDRESS of a stored secret — the coordinate, never
// the value.
//
// It exists because both ends of the wire need to agree on what a secret is
// named, and neither may depend on the other to say so: pkg/store owns the
// ZapDB keyspace, pkg/zapclient runs inside every consumer, and a client that
// had to import the server's storage package to name a record would drag the
// database into every binary that reads one secret. One coordinate type, in one
// leaf package, imported by store, zapserver, zapclient and the HTTP face
// alike — so "which record" means exactly the same thing everywhere.
//
// Nothing here can carry a value. That is the point: enumeration is a
// coordinate operation, and the type system, not a code review, is what keeps a
// listing from ever returning plaintext.
package secret

// Ref is a stored secret's full coordinate — the complete answer to "what is in
// this store". It has no value field, so an enumeration is structurally
// incapable of returning a secret, and it carries the path and env alongside
// the name so a listed record is never mistaken for a different environment's
// record of the same name.
//
// A Ref feeds straight back into Get and Delete. That round trip is the
// invariant: whatever a listing names, a read of that same coordinate must
// find. A list that answers with bare names cannot honor it, because a name
// alone does not say which path or which environment it came from.
type Ref struct {
	Path string `json:"path"`
	Env  string `json:"env"`
	Name string `json:"name"`
}

// Query selects a set of stored secrets. The ZERO Query selects every record:
// a store you cannot ask "what is in you" cannot be audited, rotated, or
// checked for coverage, so "everything" must be expressible.
type Query struct {
	// Path is a subtree root. It selects the secrets stored at this path AND
	// at every path beneath it; "" selects the whole store. Matching is on the
	// segment boundary, so "deploy" reaches "deploy/ci" but never "deployfoo".
	Path string

	// Env restricts the result to one environment. "" means EVERY environment.
	// There is deliberately no default env here: env is a component of the
	// storage key, so a listing that silently picked one would report an empty
	// store while another env held every record — indistinguishable, from the
	// outside, from a store that is genuinely empty.
	Env string
}
