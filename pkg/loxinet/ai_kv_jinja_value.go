/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ai_kv_jinja_value.go — the template executor's value model.
 *
 * Values mirror the Python objects the engine's renderer sees: nil (None),
 * bool, int, string, kvJjMarkup (a |safe string), []any (list), kvJjTuple,
 * *kvJjDict (insertion-ordered str-keyed dict), *kvJjNS (namespace()),
 * kvJjUndef (Undefined), and callables (*kvJjMacro, kvJjBuiltin). Floats are
 * deliberately absent: no pinned chat template needs one, and float
 * formatting is where a Go rendering would drift from Python's repr.
 *
 * Every conversion to text (output, ~, |string, repr, |tojson) follows the
 * Python rule it stands in for byte-for-byte; the rows in
 * cicd/common/kv_hash/fixtures/kv_jinja_construct_parity.json are the proof.
 */

package loxinet

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// kvJjMarkup is a string marked safe (|safe). With autoescape off it renders
// and concatenates with ~ as a plain string, but Python's Markup.__add__
// HTML-escapes a plain operand, so + involving it is refused.
type kvJjMarkup string

// kvJjTuple is a Python tuple: a list for iteration, a tuple for repr.
type kvJjTuple []any

// kvJjDict is a str-keyed dict that keeps insertion order, as Python's does
// — iteration, |items, |tojson and repr all observe that order.
type kvJjDict struct {
	keys []string
	vals map[string]any
}

func kvJjNewDict() *kvJjDict { return &kvJjDict{vals: map[string]any{}} }

func (d *kvJjDict) set(k string, v any) {
	if _, ok := d.vals[k]; !ok {
		d.keys = append(d.keys, k)
	}
	d.vals[k] = v
}

func (d *kvJjDict) get(k string) (any, bool) {
	v, ok := d.vals[k]
	return v, ok
}

// kvJjFromGo converts a caller-supplied context value into the value model.
// map[string]any has no order, so its keys are taken sorted — callers that
// need Python's insertion order (the chat context) build *kvJjDict directly.
func kvJjFromGo(v any) any {
	switch x := v.(type) {
	case map[string]any:
		d := kvJjNewDict()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			d.set(k, kvJjFromGo(x[k]))
		}
		return d
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = kvJjFromGo(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = kvJjFromGo(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	}
	return v
}

// kvJjSeq returns the items of a list or tuple.
func kvJjSeq(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case kvJjTuple:
		return x, true
	}
	return nil, false
}

// kvJjStr returns the text of a string or markup value.
func kvJjStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case kvJjMarkup:
		return string(x), true
	}
	return "", false
}

func kvJjTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int:
		return "int"
	case float64:
		return "float"
	case string, kvJjMarkup:
		return "str"
	case []any:
		return "list"
	case kvJjTuple:
		return "tuple"
	case *kvJjDict:
		return "dict"
	case *kvJjNS:
		return "Namespace"
	case kvJjUndef:
		return "Undefined"
	case *kvJjMacro, kvJjBuiltin:
		return "callable"
	}
	return fmt.Sprintf("%T", v)
}

func kvJjTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case kvJjUndef:
		return false
	case bool:
		return x
	case int:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case kvJjMarkup:
		return x != ""
	case []any:
		return len(x) != 0
	case kvJjTuple:
		return len(x) != 0
	case *kvJjDict:
		return len(x.keys) != 0
	}
	return true
}

// kvJjToStr is Python str() as Jinja applies it to output, ~ and |string.
// Undefined renders as "".
func kvJjToStr(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case kvJjMarkup:
		return string(x), nil
	case kvJjUndef:
		return "", nil
	case nil, bool, int, float64, []any, kvJjTuple, *kvJjDict:
		return kvJjRepr(v)
	}
	return "", fmt.Errorf("cannot render value of type %s", kvJjTypeName(v))
}

// kvJjRepr is Python repr() for the value model.
func kvJjRepr(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "None", nil
	case bool:
		if x {
			return "True", nil
		}
		return "False", nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		return kvJjPyFloatRepr(x), nil
	case string:
		return kvJjPyStrRepr(x), nil
	case kvJjMarkup:
		// Markup.__repr__ is "Markup('...')"; no template prints one.
		return "", fmt.Errorf("repr of markup is unsupported")
	case []any, kvJjTuple:
		items, _ := kvJjSeq(v)
		var b strings.Builder
		_, tuple := v.(kvJjTuple)
		if tuple {
			b.WriteByte('(')
		} else {
			b.WriteByte('[')
		}
		for i, it := range items {
			if i > 0 {
				b.WriteString(", ")
			}
			s, err := kvJjRepr(it)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		if tuple {
			if len(items) == 1 {
				b.WriteByte(',')
			}
			b.WriteByte(')')
		} else {
			b.WriteByte(']')
		}
		return b.String(), nil
	case *kvJjDict:
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(kvJjPyStrRepr(k))
			b.WriteString(": ")
			s, err := kvJjRepr(x.vals[k])
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		b.WriteByte('}')
		return b.String(), nil
	}
	return "", fmt.Errorf("repr of %s is unsupported", kvJjTypeName(v))
}

// kvJjPyStrRepr is CPython's unicode_repr: single quotes unless the text
// holds a single quote and no double quote; \\, the quote, \t \n \r escaped;
// other non-printable code points as \xNN / \uNNNN / \UNNNNNNNN.
func kvJjPyStrRepr(s string) string {
	q := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case kvJjPyPrintable(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(q)
	return b.String()
}

// kvJjPyPrintable approximates Python's str.isprintable for non-ASCII code
// points: separators other than the ASCII space and the Other categories
// (control, format, surrogate, private use, unassigned) are not printable.
func kvJjPyPrintable(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	if unicode.In(r, unicode.Zl, unicode.Zp, unicode.Zs, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs) {
		return false
	}
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// kvJjEqual is Python ==: bool and int compare numerically, sequences and
// dicts element-wise, Undefined equals only Undefined.
func kvJjEqual(l, r any) bool {
	if li, ok := kvJjNum(l); ok {
		ri, ok := kvJjNum(r)
		return ok && li == ri
	}
	if ls, ok := kvJjStr(l); ok {
		rs, ok := kvJjStr(r)
		return ok && ls == rs
	}
	switch lv := l.(type) {
	case nil:
		return r == nil
	case kvJjUndef:
		_, ok := r.(kvJjUndef)
		return ok
	case []any, kvJjTuple:
		_, lt := l.(kvJjTuple)
		_, rt := r.(kvJjTuple)
		if lt != rt {
			return false
		}
		a, _ := kvJjSeq(l)
		b, ok := kvJjSeq(r)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !kvJjEqual(a[i], b[i]) {
				return false
			}
		}
		return true
	case *kvJjDict:
		rv, ok := r.(*kvJjDict)
		if !ok || len(lv.keys) != len(rv.keys) {
			return false
		}
		for _, k := range lv.keys {
			o, ok := rv.vals[k]
			if !ok || !kvJjEqual(lv.vals[k], o) {
				return false
			}
		}
		return true
	case *kvJjNS:
		return l == r
	}
	return false
}

// kvJjNum returns an int or bool as a Python number.
func kvJjNum(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// kvJjPyJSON is json.dumps as transformers' tojson override calls it.
type kvJjPyJSON struct {
	ensureASCII bool
	indent      int // -1 = None
	itemSep     string
	keySep      string
	sortKeys    bool
}

func (j *kvJjPyJSON) dump(v any) (string, error) {
	var b strings.Builder
	if err := j.write(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (j *kvJjPyJSON) newline(b *strings.Builder, depth int) {
	if j.indent < 0 {
		return
	}
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", j.indent*depth))
}

func (j *kvJjPyJSON) write(b *strings.Builder, v any, depth int) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(x))
	case float64:
		// json.dumps prints a float with float.__repr__.
		b.WriteString(kvJjPyFloatRepr(x))
	case string:
		j.writeStr(b, x)
	case kvJjMarkup:
		j.writeStr(b, string(x))
	case []any, kvJjTuple:
		items, _ := kvJjSeq(v)
		if len(items) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteByte('[')
		for i, it := range items {
			if i > 0 {
				b.WriteString(j.itemSep)
			}
			j.newline(b, depth+1)
			if err := j.write(b, it, depth+1); err != nil {
				return err
			}
		}
		j.newline(b, depth)
		b.WriteByte(']')
	case *kvJjDict:
		if len(x.keys) == 0 {
			b.WriteString("{}")
			return nil
		}
		keys := x.keys
		if j.sortKeys {
			keys = append([]string(nil), keys...)
			sort.Strings(keys)
		}
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(j.itemSep)
			}
			j.newline(b, depth+1)
			j.writeStr(b, k)
			b.WriteString(j.keySep)
			if err := j.write(b, x.vals[k], depth+1); err != nil {
				return err
			}
		}
		j.newline(b, depth)
		b.WriteByte('}')
	default:
		return fmt.Errorf("object of type %s is not JSON serializable", kvJjTypeName(v))
	}
	return nil
}

// writeStr follows CPython's py_encode_basestring(_ascii).
func (j *kvJjPyJSON) writeStr(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case j.ensureASCII && r > 0x7e:
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800|(r>>10)&0x3ff, 0xdc00|r&0x3ff)
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// kvJjPyFloatRepr is Python's float.__repr__ (float_repr_style "short"):
// the shortest digit string that round-trips, printed in positional
// notation when the decimal exponent is in [-4, 16) and otherwise in
// scientific notation with a signed, at least two-digit exponent — so 1.0,
// 100000.0, 0.0001, 1e-05, 1e+16, 1.5e+20. Floats only reach the value model
// through JSON numbers carrying a fraction or exponent (Python's json.loads
// makes those floats), so inf and nan are unreachable; they print as Python
// does for completeness.
func kvJjPyFloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case f == 0:
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±xx, shortest digits
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	if exp < -4 || exp >= 16 {
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		return fmt.Sprintf("%s%se%+03d", sign, m, exp)
	}
	if exp >= 0 {
		if len(digits) <= exp+1 {
			return sign + digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		}
		return sign + digits[:exp+1] + "." + digits[exp+1:]
	}
	return sign + "0." + strings.Repeat("0", -exp-1) + digits
}
