// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.containsWord

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Matches if the parameter string is found in the input as a whole word: the
// characters immediately before and after the match must not be ASCII letters
// (A-Z, a-z), or the match must touch the input boundaries. Digits, underscore
// and any non-letter byte count as word boundaries, matching ModSecurity's
// containsWord. Matching is byte-oriented and case-sensitive, like @contains.
// Supports macro expansion for dynamic string matching.
//
// Arguments:
// String to search for within the input. Supports variable expansion using
// %{VAR} syntax. An empty parameter is valid and matches every input, as in
// ModSecurity; it is not a load error.
//
// Returns:
// true if the parameter is found in the input on word boundaries, false
// otherwise. An empty input never matches a non-empty parameter.
//
// Example:
// ```seclang
// # Matches "admin" but not "administrator"
// SecRule REQUEST_URI "@containsWord admin" "id:160,deny"
// ```
type containsWord struct {
	// data is nil when the parameter is empty; an empty parameter matches
	// every input (ModSecurity semantics).
	data macro.Macro
}

var _ plugintypes.Operator = (*containsWord)(nil)

func newContainsWord(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	m, err := newMacroAllowEmpty(options.Arguments)
	if err != nil {
		return nil, err
	}
	return &containsWord{data: m}, nil
}

func (o *containsWord) Evaluate(tx plugintypes.TransactionState, value string) bool {
	data := expandMacro(tx, o.data)
	if data == "" {
		// An empty parameter matches every input (ModSecurity semantics).
		return true
	}
	if value == "" {
		return false
	}
	if value == data {
		return true
	}

	dataLen := len(data)
	valueLen := len(value)
	for i := 0; i <= valueLen-dataLen; {
		idx := strings.Index(value[i:], data)
		if idx == -1 {
			return false
		}
		pos := i + idx
		end := pos + dataLen
		leftBoundary := pos == 0 || !isASCIILetter(value[pos-1])
		rightBoundary := end == valueLen || !isASCIILetter(value[end])
		if leftBoundary && rightBoundary {
			return true
		}
		i = pos + 1
	}
	return false
}

// isASCIILetter reports whether c is an ASCII letter, the only character class
// ModSecurity's containsWord treats as a word character.
func isASCIILetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func init() {
	Register("containsWord", newContainsWord)
}
