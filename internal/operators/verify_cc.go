// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.verifyCC

package operators

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Matches if the input contains a string matched by the parameter regular
// expression whose digits pass the Luhn Mod-10 check (ISO 2894/ANSI 4.13),
// i.e. a candidate credit card number with a valid checksum. Non-digit
// characters inside a candidate (spaces, dashes) are ignored by the checksum,
// as in ModSecurity's verifyCC. When the rule has the capture action, the
// matching candidate is captured into TX.0.
//
// Arguments:
// Regular expression (RE2 syntax) selecting the candidate card numbers, e.g.
// a card prefix pattern. The pattern is compiled with the same default flags
// as the @rx operator (dotall, plus multiline unless the
// coraza.rule.no_regex_multiline build tag is set). A missing argument or an
// invalid expression is a load-time error.
//
// Returns:
// true if a regex match in the input passes the Luhn check, false otherwise.
// An empty input never matches.
//
// Example:
// ```seclang
// # Block requests carrying a Visa card number in any argument
// SecRule ARGS "@verifyCC (?:^|[^\d])(4\d{15})(?:[^\d]|$)" "id:180,deny,log"
// ```
type verifyCC struct {
	re *regexp.Regexp
}

var _ plugintypes.Operator = (*verifyCC)(nil)

func newVerifyCC(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	if data == "" {
		return nil, errors.New("missing @verifyCC regular expression argument")
	}

	// Same default flags as the @rx operator: dotall, plus multiline unless
	// the coraza.rule.no_regex_multiline build tag is set.
	var wrapped string
	if shouldNotUseMultilineRegexesOperatorByDefault {
		wrapped = "(?s)" + data
	} else {
		wrapped = "(?sm)" + data
	}

	re, err := memoizeDo(options.Memoizer, memoizeKey("verifycc", wrapped), func() (any, error) {
		return regexp.Compile(wrapped)
	})
	if err != nil {
		return nil, fmt.Errorf("invalid @verifyCC regular expression %q: %w", data, err)
	}
	return &verifyCC{re: re.(*regexp.Regexp)}, nil
}

func (o *verifyCC) Evaluate(tx plugintypes.TransactionState, value string) bool {
	// Candidates are the leftmost non-overlapping regex matches, evaluated
	// against the whole input so ^ and $ keep their absolute meaning.
	for _, loc := range o.re.FindAllStringIndex(value, -1) {
		match := value[loc[0]:loc[1]]
		if luhnVerify(match) {
			if tx.Capturing() {
				tx.CaptureField(0, match)
			}
			return true
		}
	}
	return false
}

// luhnWeightTable is the weighted lookup table from ModSecurity's luhnVerify:
// i*2, minus 9 when i*2 > 9.
var luhnWeightTable = [10]int{0, 2, 4, 6, 8, 1, 3, 5, 7, 9}

// luhnVerify runs the Luhn Mod-10 check over the digits of the candidate,
// ignoring non-digit characters, exactly as ModSecurity's verifyCC does.
func luhnVerify(candidate string) bool {
	var sum [2]int
	odd := 0
	digits := 0
	for i := 0; i < len(candidate); i++ {
		c := candidate[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if odd == 0 {
			sum[0] += luhnWeightTable[d]
			sum[1] += d
		} else {
			sum[0] += d
			sum[1] += luhnWeightTable[d]
		}
		odd = 1 - odd
		digits++
	}
	if digits == 0 {
		return false
	}
	return sum[odd]%10 == 0
}

func init() {
	Register("verifyCC", newVerifyCC)
}
