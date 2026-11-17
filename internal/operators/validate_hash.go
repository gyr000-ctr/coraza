// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateHash

package operators

import (
	"errors"
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// hashHexLengths maps each supported hash algorithm to the length of its hex
// digest in bytes.
var hashHexLengths = map[string]int{
	"md5":    32,
	"sha1":   40,
	"sha224": 56,
	"sha256": 64,
	"sha384": 96,
	"sha512": 128,
}

// Description:
// Validates that the input is a well-formed hex digest of the hash algorithm
// named by the parameter: exactly the digest length of the algorithm and only
// hexadecimal characters (both upper and lower case are accepted, hex is case
// insensitive by convention). The algorithm name is matched strictly and
// case-sensitively.
//
// Arguments:
// Hash algorithm name, one of: md5, sha1, sha224, sha256, sha384, sha512.
// A missing argument or an unknown algorithm is a load-time error.
//
// Returns:
// true if the input is exactly the hex digest of the named algorithm, false
// otherwise. Empty, shorter, longer or non-hex inputs do not match; the
// rejection reason is recorded in the transaction debug log.
//
// Example:
// ```seclang
// # Reject a token that is not an MD5 hex digest
// SecRule ARGS:token "!@validateHash md5" "id:170,deny,msg:'Invalid token format'"
// ```
type validateHash struct {
	algorithm string
	hexLen    int
}

var _ plugintypes.Operator = (*validateHash)(nil)

func newValidateHash(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	if data == "" {
		return nil, errors.New("missing @validateHash algorithm argument, expected one of: md5, sha1, sha224, sha256, sha384, sha512")
	}
	hexLen, ok := hashHexLengths[data]
	if !ok {
		return nil, fmt.Errorf("invalid @validateHash algorithm %q, expected one of: md5, sha1, sha224, sha256, sha384, sha512", data)
	}
	return &validateHash{algorithm: data, hexLen: hexLen}, nil
}

func (o *validateHash) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if len(value) != o.hexLen {
		tx.DebugLogger().Debug().
			Str("operator", "validateHash").
			Str("algorithm", o.algorithm).
			Int("input_length", len(value)).
			Int("expected_length", o.hexLen).
			Msg("validateHash: input length does not match the algorithm hex digest length")
		return false
	}
	for i := 0; i < len(value); i++ {
		if !isHashHexDigit(value[i]) {
			tx.DebugLogger().Debug().
				Str("operator", "validateHash").
				Str("algorithm", o.algorithm).
				Int("offset", i).
				Msg("validateHash: non-hexadecimal character in input")
			return false
		}
	}
	return true
}

// isHashHexDigit reports whether c is an ASCII hexadecimal digit. It is local
// to this file because the identical helper in validate_url_encoding.go is
// compiled out when that operator is disabled via build tag.
func isHashHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func init() {
	Register("validateHash", newValidateHash)
}
