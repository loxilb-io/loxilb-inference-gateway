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
 * ai_kv_jinja.go — minimal Jinja template executor for profile-pinned chat
 * templates.
 *
 * The KV-exact chat surface must render byte-identically to the engine's
 * apply_chat_template. Engines render with HF transformers' Jinja environment
 * (trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=False), so this
 * executor implements those exact whitespace semantics plus the language
 * subset the pinned production templates use: {% if/elif/else %}, {% for %}
 * with loop.first/last/index0, {% set %} (including namespace attribute
 * assignment), output statements with -trim markers, string/int/bool
 * literals, attribute/subscript/slice access ([::-1] included), the
 * trim/length/tojson filters, the defined/string/true/false/none tests,
 * and the startswith/endswith/split/strip/lstrip/rstrip string methods.
 *
 * Anything outside the subset fails loudly: unknown constructs are compile
 * errors, unknown filters/tests/methods and type mismatches are render
 * errors. A render error on a strict rule surfaces as a runtime fault (the
 * caller's contract), never as silently different bytes — parity with the
 * offline HF oracle is proven case-by-case in ai_kv_jinja_test.go against
 * cicd/common/kv_hash/fixtures/kv_chat_render_parity.json.
 */

package loxinet

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// kvJjUndef is the Jinja Undefined value: falsy, renders as "", equals
// nothing, and raises on any stricter use (concat, iteration, methods).
type kvJjUndef struct{ name string }

// kvJjNS is a namespace() object: the one mutable-by-reference value in the
// subset (Jinja for-loop scopes are per-iteration, so templates thread
// cross-iteration state through namespace attributes).
type kvJjNS struct{ attrs map[string]any }

// kvJinjaTemplate is a compiled template. Compilation is pure; Render may be
// called concurrently.
type kvJinjaTemplate struct {
	nodes []kvJjNode
}

type kvJjError struct {
	pos int
	msg string
}

func (e *kvJjError) Error() string {
	return fmt.Sprintf("jinja: offset %d: %s", e.pos, e.msg)
}

func kvJjErrf(pos int, format string, a ...any) error {
	return &kvJjError{pos: pos, msg: fmt.Sprintf(format, a...)}
}

// ---------------------------------------------------------------------------
// Segment lexer: split source into text and {% %} / {{ }} / {# #} tags, then
// apply the whitespace-control rules the engine environment uses.

type kvJjSegKind int

const (
	kvJjSegText kvJjSegKind = iota
	kvJjSegBlock
	kvJjSegOutput
	kvJjSegComment
)

type kvJjSeg struct {
	kind      kvJjSegKind
	body      string // tag interior (trim markers removed) or raw text
	pos       int
	trimLeft  bool
	trimRight bool
}

func kvJjLex(src string) ([]kvJjSeg, error) {
	// keep_trailing_newline=False: exactly one trailing newline is dropped
	// before any other processing.
	src = strings.TrimSuffix(src, "\n")

	var segs []kvJjSeg
	i := 0
	for i < len(src) {
		open := strings.IndexByte(src[i:], '{')
		for open >= 0 {
			j := i + open
			if j+1 < len(src) && (src[j+1] == '%' || src[j+1] == '{' || src[j+1] == '#') {
				break
			}
			open = strings.IndexByte(src[i+open+1:], '{')
			if open >= 0 {
				open += j - i + 1
			}
		}
		if open < 0 {
			segs = append(segs, kvJjSeg{kind: kvJjSegText, body: src[i:], pos: i})
			break
		}
		start := i + open
		if start > i {
			segs = append(segs, kvJjSeg{kind: kvJjSegText, body: src[i:start], pos: i})
		}
		var kind kvJjSegKind
		var closer string
		switch src[start+1] {
		case '%':
			kind, closer = kvJjSegBlock, "%}"
		case '{':
			kind, closer = kvJjSegOutput, "}}"
		case '#':
			kind, closer = kvJjSegComment, "#}"
		}
		end, err := kvJjFindClose(src, start+2, closer)
		if err != nil {
			return nil, err
		}
		body := src[start+2 : end]
		seg := kvJjSeg{kind: kind, pos: start}
		if strings.HasPrefix(body, "-") {
			seg.trimLeft = true
			body = body[1:]
		}
		if strings.HasSuffix(body, "-") {
			seg.trimRight = true
			body = body[:len(body)-1]
		}
		seg.body = strings.TrimSpace(body)
		segs = append(segs, seg)
		i = end + 2
	}

	// Whitespace control, in the engine environment's order: explicit -
	// markers strip all adjacent whitespace; otherwise lstrip_blocks removes
	// a line-leading indent before a block/comment tag and trim_blocks
	// removes the single newline after one. Output tags get neither default.
	for k := range segs {
		if segs[k].kind != kvJjSegText {
			continue
		}
		if k > 0 {
			prev := &segs[k-1]
			if prev.trimRight {
				segs[k].body = strings.TrimLeft(segs[k].body, " \t\r\n")
			} else if prev.kind == kvJjSegBlock || prev.kind == kvJjSegComment {
				segs[k].body = strings.TrimPrefix(segs[k].body, "\n")
			}
		}
		if k+1 < len(segs) {
			next := &segs[k+1]
			if next.trimLeft {
				segs[k].body = strings.TrimRight(segs[k].body, " \t\r\n")
			} else if next.kind == kvJjSegBlock || next.kind == kvJjSegComment {
				t := segs[k].body
				cut := len(t)
				for cut > 0 && (t[cut-1] == ' ' || t[cut-1] == '\t') {
					cut--
				}
				// Strip only a run that starts at a line start (or template
				// start) — mid-line whitespace before a tag is content.
				if cut < len(t) && (cut == 0 && segs[k].pos == 0 || cut > 0 && t[cut-1] == '\n') {
					segs[k].body = t[:cut]
				}
			}
		}
	}
	return segs, nil
}

// kvJjFindClose finds the tag closer, skipping quoted strings (template
// string literals may contain braces and real newlines).
func kvJjFindClose(src string, from int, closer string) (int, error) {
	for i := from; i < len(src)-1; i++ {
		c := src[i]
		if c == '\'' || c == '"' {
			q := c
			i++
			for i < len(src) {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == q {
					break
				}
				i++
			}
			if i >= len(src) {
				return 0, kvJjErrf(from, "unterminated string literal")
			}
			continue
		}
		if c == closer[0] && src[i+1] == closer[1] {
			// A '-' right-trim marker sits between body and closer.
			return i, nil
		}
	}
	return 0, kvJjErrf(from, "unterminated tag (missing %s)", closer)
}

// ---------------------------------------------------------------------------
// Statement parser.

type kvJjNode interface {
	exec(rt *kvJjRT, sb *strings.Builder) error
}

type kvJjText struct{ s string }

type kvJjOutput struct {
	e   kvJjExpr
	pos int
}

type kvJjIf struct {
	conds  []kvJjExpr // one per if/elif branch
	bodies [][]kvJjNode
	els    []kvJjNode
}

type kvJjFor struct {
	v    string
	seq  kvJjExpr
	body []kvJjNode
	pos  int
}

type kvJjSet struct {
	name string
	attr string // non-empty for namespace attribute assignment
	e    kvJjExpr
	pos  int
}

// kvJinjaCompile parses template source into an executable node tree.
func kvJinjaCompile(src string) (*kvJinjaTemplate, error) {
	segs, err := kvJjLex(src)
	if err != nil {
		return nil, err
	}
	p := &kvJjSegParser{segs: segs}
	nodes, err := p.parseBody(nil)
	if err != nil {
		return nil, err
	}
	return &kvJinjaTemplate{nodes: nodes}, nil
}

type kvJjSegParser struct {
	segs []kvJjSeg
	i    int
}

// parseBody parses statements until one of the terminator keywords (endif,
// elif, else, endfor) appears, which is left un-consumed for the caller.
func (p *kvJjSegParser) parseBody(until []string) ([]kvJjNode, error) {
	var nodes []kvJjNode
	for p.i < len(p.segs) {
		seg := p.segs[p.i]
		switch seg.kind {
		case kvJjSegText:
			p.i++
			if seg.body != "" {
				nodes = append(nodes, &kvJjText{s: seg.body})
			}
		case kvJjSegComment:
			p.i++
		case kvJjSegOutput:
			p.i++
			e, err := kvJjParseExprAll(seg.body, seg.pos)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, &kvJjOutput{e: e, pos: seg.pos})
		case kvJjSegBlock:
			kw := seg.body
			if sp := strings.IndexAny(kw, " \t\r\n"); sp >= 0 {
				kw = kw[:sp]
			}
			for _, u := range until {
				if kw == u {
					return nodes, nil
				}
			}
			n, err := p.parseBlock(seg)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, n)
		}
	}
	if len(until) != 0 {
		return nil, kvJjErrf(0, "unexpected end of template (missing %s)", until[0])
	}
	return nodes, nil
}

func (p *kvJjSegParser) parseBlock(seg kvJjSeg) (kvJjNode, error) {
	body := seg.body
	kw := body
	rest := ""
	if sp := strings.IndexAny(body, " \t\r\n"); sp >= 0 {
		kw, rest = body[:sp], strings.TrimSpace(body[sp:])
	}
	switch kw {
	case "if":
		p.i++
		return p.parseIf(rest, seg.pos)
	case "for":
		p.i++
		return p.parseFor(rest, seg.pos)
	case "set":
		p.i++
		return kvJjParseSet(rest, seg.pos)
	default:
		return nil, kvJjErrf(seg.pos, "unsupported block %q", kw)
	}
}

func (p *kvJjSegParser) parseIf(condSrc string, pos int) (kvJjNode, error) {
	n := &kvJjIf{}
	for {
		cond, err := kvJjParseExprAll(condSrc, pos)
		if err != nil {
			return nil, err
		}
		body, err := p.parseBody([]string{"elif", "else", "endif"})
		if err != nil {
			return nil, err
		}
		n.conds = append(n.conds, cond)
		n.bodies = append(n.bodies, body)
		term := p.segs[p.i]
		p.i++
		kw := term.body
		rest := ""
		if sp := strings.IndexAny(kw, " \t\r\n"); sp >= 0 {
			kw, rest = term.body[:sp], strings.TrimSpace(term.body[sp:])
		}
		switch kw {
		case "endif":
			return n, nil
		case "elif":
			condSrc, pos = rest, term.pos
		case "else":
			els, err := p.parseBody([]string{"endif"})
			if err != nil {
				return nil, err
			}
			n.els = els
			p.i++ // consume endif
			return n, nil
		}
	}
}

func (p *kvJjSegParser) parseFor(head string, pos int) (kvJjNode, error) {
	inIdx := strings.Index(head, " in ")
	if inIdx < 0 {
		return nil, kvJjErrf(pos, "for: expected \"<var> in <expr>\"")
	}
	v := strings.TrimSpace(head[:inIdx])
	if !kvJjIsIdent(v) {
		return nil, kvJjErrf(pos, "for: unsupported loop target %q", v)
	}
	seq, err := kvJjParseExprAll(head[inIdx+4:], pos)
	if err != nil {
		return nil, err
	}
	body, err := p.parseBody([]string{"endfor"})
	if err != nil {
		return nil, err
	}
	p.i++ // consume endfor
	return &kvJjFor{v: v, seq: seq, body: body, pos: pos}, nil
}

func kvJjParseSet(src string, pos int) (kvJjNode, error) {
	eq := -1
	depth := 0
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '\'', '"':
			q := src[i]
			for i++; i < len(src) && src[i] != q; i++ {
				if src[i] == '\\' {
					i++
				}
			}
		case '=':
			if depth == 0 && (i+1 >= len(src) || src[i+1] != '=') && (i == 0 || src[i-1] != '!' && src[i-1] != '<' && src[i-1] != '>' && src[i-1] != '=') {
				eq = i
			}
		}
		if eq >= 0 {
			break
		}
	}
	if eq < 0 {
		return nil, kvJjErrf(pos, "set: expected \"<target> = <expr>\"")
	}
	target := strings.TrimSpace(src[:eq])
	name, attr := target, ""
	if dot := strings.IndexByte(target, '.'); dot >= 0 {
		name, attr = target[:dot], target[dot+1:]
		if !kvJjIsIdent(attr) {
			return nil, kvJjErrf(pos, "set: unsupported target %q", target)
		}
	}
	if !kvJjIsIdent(name) {
		return nil, kvJjErrf(pos, "set: unsupported target %q", target)
	}
	e, err := kvJjParseExprAll(src[eq+1:], pos)
	if err != nil {
		return nil, err
	}
	return &kvJjSet{name: name, attr: attr, e: e, pos: pos}, nil
}

func kvJjIsIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Expression lexer + parser (Jinja precedence: or < and < not < comparison/in
// < add/sub < unary < postfix, with filters and tests binding at postfix
// level so `messages|length - 1` is `(messages|length) - 1`).

type kvJjTok struct {
	kind string // ident, int, str, op, end
	s    string
	n    int
	pos  int
}

type kvJjExprLexer struct {
	src  string
	base int
	i    int
	toks []kvJjTok
}

func kvJjLexExpr(src string, base int) ([]kvJjTok, error) {
	l := &kvJjExprLexer{src: src, base: base}
	for l.i < len(l.src) {
		c := l.src[l.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			l.i++
		case c == '\'' || c == '"':
			if err := l.lexString(c); err != nil {
				return nil, err
			}
		case c >= '0' && c <= '9':
			j := l.i
			for j < len(l.src) && l.src[j] >= '0' && l.src[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(l.src[l.i:j])
			l.toks = append(l.toks, kvJjTok{kind: "int", n: n, pos: base + l.i})
			l.i = j
		case c == '_' || unicode.IsLetter(rune(c)):
			j := l.i
			for j < len(l.src) {
				r := l.src[j]
				if r == '_' || unicode.IsLetter(rune(r)) || unicode.IsDigit(rune(r)) {
					j++
					continue
				}
				break
			}
			l.toks = append(l.toks, kvJjTok{kind: "ident", s: l.src[l.i:j], pos: base + l.i})
			l.i = j
		default:
			two := ""
			if l.i+1 < len(l.src) {
				two = l.src[l.i : l.i+2]
			}
			switch two {
			case "==", "!=", "<=", ">=":
				l.toks = append(l.toks, kvJjTok{kind: "op", s: two, pos: base + l.i})
				l.i += 2
				continue
			}
			switch c {
			case '+', '-', '<', '>', '(', ')', '[', ']', '.', ',', ':', '|', '=', '~':
				l.toks = append(l.toks, kvJjTok{kind: "op", s: string(c), pos: base + l.i})
				l.i++
			default:
				return nil, kvJjErrf(base+l.i, "unsupported character %q in expression", string(c))
			}
		}
	}
	l.toks = append(l.toks, kvJjTok{kind: "end", pos: base + len(src)})
	return l.toks, nil
}

func (l *kvJjExprLexer) lexString(q byte) error {
	start := l.i
	l.i++
	var b strings.Builder
	for l.i < len(l.src) {
		c := l.src[l.i]
		if c == '\\' && l.i+1 < len(l.src) {
			switch l.src[l.i+1] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\':
				b.WriteByte('\\')
			case '\'':
				b.WriteByte('\'')
			case '"':
				b.WriteByte('"')
			default:
				// Jinja keeps unknown escapes verbatim.
				b.WriteByte('\\')
				b.WriteByte(l.src[l.i+1])
			}
			l.i += 2
			continue
		}
		if c == q {
			l.i++
			l.toks = append(l.toks, kvJjTok{kind: "str", s: b.String(), pos: l.base + start})
			return nil
		}
		b.WriteByte(c)
		l.i++
	}
	return kvJjErrf(l.base+start, "unterminated string literal")
}

type kvJjExpr interface {
	eval(rt *kvJjRT) (any, error)
}

type kvJjExprParser struct {
	toks []kvJjTok
	i    int
}

func kvJjParseExprAll(src string, base int) (kvJjExpr, error) {
	toks, err := kvJjLexExpr(src, base)
	if err != nil {
		return nil, err
	}
	p := &kvJjExprParser{toks: toks}
	e, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.cur().kind != "end" {
		return nil, kvJjErrf(p.cur().pos, "unexpected %q after expression", p.cur().s)
	}
	return e, nil
}

func (p *kvJjExprParser) cur() kvJjTok  { return p.toks[p.i] }
func (p *kvJjExprParser) next() kvJjTok { t := p.toks[p.i]; p.i++; return t }

func (p *kvJjExprParser) accept(kind, s string) bool {
	t := p.cur()
	if t.kind == kind && (s == "" || t.s == s) {
		p.i++
		return true
	}
	return false
}

func (p *kvJjExprParser) parseOr() (kvJjExpr, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept("ident", "or") {
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &kvJjBool{op: "or", l: l, r: r}
	}
	return l, nil
}

func (p *kvJjExprParser) parseAnd() (kvJjExpr, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.accept("ident", "and") {
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = &kvJjBool{op: "and", l: l, r: r}
	}
	return l, nil
}

func (p *kvJjExprParser) parseNot() (kvJjExpr, error) {
	if p.accept("ident", "not") {
		e, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &kvJjNot{e: e}, nil
	}
	return p.parseCompare()
}

func (p *kvJjExprParser) parseCompare() (kvJjExpr, error) {
	l, err := p.parseAdd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.cur()
		if t.kind == "op" && (t.s == "==" || t.s == "!=" || t.s == "<" || t.s == "<=" || t.s == ">" || t.s == ">=") {
			p.i++
			r, err := p.parseAdd()
			if err != nil {
				return nil, err
			}
			l = &kvJjCmp{op: t.s, l: l, r: r, pos: t.pos}
			continue
		}
		if t.kind == "ident" && t.s == "in" {
			p.i++
			r, err := p.parseAdd()
			if err != nil {
				return nil, err
			}
			l = &kvJjIn{l: l, r: r, pos: t.pos}
			continue
		}
		if t.kind == "ident" && t.s == "not" && p.toks[p.i+1].kind == "ident" && p.toks[p.i+1].s == "in" {
			p.i += 2
			r, err := p.parseAdd()
			if err != nil {
				return nil, err
			}
			l = &kvJjNot{e: &kvJjIn{l: l, r: r, pos: t.pos}}
			continue
		}
		return l, nil
	}
}

func (p *kvJjExprParser) parseAdd() (kvJjExpr, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.cur()
		if t.kind == "op" && (t.s == "+" || t.s == "-" || t.s == "~") {
			p.i++
			r, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			l = &kvJjArith{op: t.s, l: l, r: r, pos: t.pos}
			continue
		}
		return l, nil
	}
}

func (p *kvJjExprParser) parseUnary() (kvJjExpr, error) {
	if t := p.cur(); t.kind == "op" && t.s == "-" {
		p.i++
		e, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &kvJjNeg{e: e, pos: t.pos}, nil
	}
	return p.parsePostfix()
}

func (p *kvJjExprParser) parsePostfix() (kvJjExpr, error) {
	e, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.cur()
		switch {
		case t.kind == "op" && t.s == ".":
			p.i++
			name := p.next()
			if name.kind != "ident" {
				return nil, kvJjErrf(name.pos, "expected attribute name after \".\"")
			}
			if p.accept("op", "(") {
				args, err := p.parseArgs()
				if err != nil {
					return nil, err
				}
				e = &kvJjMethod{obj: e, name: name.s, args: args, pos: name.pos}
			} else {
				e = &kvJjAttr{obj: e, name: name.s, pos: name.pos}
			}
		case t.kind == "op" && t.s == "[":
			p.i++
			e, err = p.parseSubscript(e, t.pos)
			if err != nil {
				return nil, err
			}
		case t.kind == "op" && t.s == "|":
			p.i++
			name := p.next()
			if name.kind != "ident" {
				return nil, kvJjErrf(name.pos, "expected filter name after \"|\"")
			}
			e = &kvJjFilter{e: e, name: name.s, pos: name.pos}
		case t.kind == "ident" && t.s == "is":
			p.i++
			negate := p.accept("ident", "not")
			name := p.next()
			if name.kind != "ident" {
				return nil, kvJjErrf(name.pos, "expected test name after \"is\"")
			}
			e = &kvJjTest{e: e, name: name.s, negate: negate, pos: name.pos}
		default:
			return e, nil
		}
	}
}

func (p *kvJjExprParser) parseSubscript(obj kvJjExpr, pos int) (kvJjExpr, error) {
	// Distinguish plain index [e] from slice [a:b:c] with any part empty.
	var parts [3]kvJjExpr
	slot := 0
	isSlice := false
	for {
		t := p.cur()
		if t.kind == "op" && t.s == ":" {
			p.i++
			isSlice = true
			slot++
			if slot > 2 {
				return nil, kvJjErrf(t.pos, "too many slice separators")
			}
			continue
		}
		if t.kind == "op" && t.s == "]" {
			p.i++
			break
		}
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		parts[slot] = e
	}
	if !isSlice {
		if parts[0] == nil {
			return nil, kvJjErrf(pos, "empty subscript")
		}
		return &kvJjIndex{obj: obj, idx: parts[0], pos: pos}, nil
	}
	return &kvJjSlice{obj: obj, start: parts[0], stop: parts[1], step: parts[2], pos: pos}, nil
}

func (p *kvJjExprParser) parseArgs() ([]kvJjExpr, error) {
	var args []kvJjExpr
	if p.accept("op", ")") {
		return args, nil
	}
	for {
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		args = append(args, e)
		if p.accept("op", ",") {
			continue
		}
		if p.accept("op", ")") {
			return args, nil
		}
		return nil, kvJjErrf(p.cur().pos, "expected \",\" or \")\" in argument list")
	}
}

func (p *kvJjExprParser) parsePrimary() (kvJjExpr, error) {
	t := p.next()
	switch t.kind {
	case "str":
		return &kvJjLit{v: t.s}, nil
	case "int":
		return &kvJjLit{v: t.n}, nil
	case "ident":
		switch t.s {
		case "true", "True":
			return &kvJjLit{v: true}, nil
		case "false", "False":
			return &kvJjLit{v: false}, nil
		case "none", "None":
			return &kvJjLit{v: nil}, nil
		case "namespace":
			if !p.accept("op", "(") {
				return nil, kvJjErrf(t.pos, "namespace requires an argument list")
			}
			kwargs := map[string]kvJjExpr{}
			if !p.accept("op", ")") {
				for {
					name := p.next()
					if name.kind != "ident" {
						return nil, kvJjErrf(name.pos, "namespace: expected keyword argument")
					}
					if !p.accept("op", "=") {
						return nil, kvJjErrf(name.pos, "namespace: expected \"=\" after %q", name.s)
					}
					e, err := p.parseOr()
					if err != nil {
						return nil, err
					}
					kwargs[name.s] = e
					if p.accept("op", ",") {
						continue
					}
					if p.accept("op", ")") {
						break
					}
					return nil, kvJjErrf(p.cur().pos, "namespace: expected \",\" or \")\"")
				}
			}
			return &kvJjNamespaceCall{kwargs: kwargs}, nil
		}
		return &kvJjVar{name: t.s, pos: t.pos}, nil
	case "op":
		if t.s == "(" {
			e, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			if !p.accept("op", ")") {
				return nil, kvJjErrf(t.pos, "missing \")\"")
			}
			return e, nil
		}
	}
	return nil, kvJjErrf(t.pos, "unexpected token %q", t.s)
}

// ---------------------------------------------------------------------------
// Expression nodes.

type kvJjLit struct{ v any }

type kvJjVar struct {
	name string
	pos  int
}

type kvJjBool struct {
	op   string
	l, r kvJjExpr
}

type kvJjNot struct{ e kvJjExpr }

type kvJjCmp struct {
	op   string
	l, r kvJjExpr
	pos  int
}

type kvJjIn struct {
	l, r kvJjExpr
	pos  int
}

type kvJjArith struct {
	op   string
	l, r kvJjExpr
	pos  int
}

type kvJjNeg struct {
	e   kvJjExpr
	pos int
}

type kvJjAttr struct {
	obj  kvJjExpr
	name string
	pos  int
}

type kvJjIndex struct {
	obj, idx kvJjExpr
	pos      int
}

type kvJjSlice struct {
	obj               kvJjExpr
	start, stop, step kvJjExpr
	pos               int
}

type kvJjMethod struct {
	obj  kvJjExpr
	name string
	args []kvJjExpr
	pos  int
}

type kvJjFilter struct {
	e    kvJjExpr
	name string
	pos  int
}

type kvJjTest struct {
	e      kvJjExpr
	name   string
	negate bool
	pos    int
}

type kvJjNamespaceCall struct{ kwargs map[string]kvJjExpr }

// ---------------------------------------------------------------------------
// Runtime.

type kvJjRT struct {
	scopes []map[string]any
}

func (rt *kvJjRT) lookup(name string) (any, bool) {
	for i := len(rt.scopes) - 1; i >= 0; i-- {
		if v, ok := rt.scopes[i][name]; ok {
			return v, true
		}
	}
	return nil, false
}

// set writes the innermost scope: Jinja assignments never escape a for-loop
// frame (templates use namespace() when they need that), while assignments
// inside {% if %} blocks share the enclosing frame.
func (rt *kvJjRT) set(name string, v any) {
	rt.scopes[len(rt.scopes)-1][name] = v
}

// Render executes the template. ctx values use the executor's value model:
// string, int, bool, []any, map[string]any, *kvJjNS.
func (t *kvJinjaTemplate) Render(ctx map[string]any) (string, error) {
	rt := &kvJjRT{scopes: []map[string]any{ctx, {}}}
	var sb strings.Builder
	for _, n := range t.nodes {
		if err := n.exec(rt, &sb); err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

func (n *kvJjText) exec(rt *kvJjRT, sb *strings.Builder) error {
	sb.WriteString(n.s)
	return nil
}

func (n *kvJjOutput) exec(rt *kvJjRT, sb *strings.Builder) error {
	v, err := n.e.eval(rt)
	if err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		sb.WriteString(x)
	case int:
		sb.WriteString(strconv.Itoa(x))
	case bool:
		// Python str() casing, for parity with the engine's renderer.
		if x {
			sb.WriteString("True")
		} else {
			sb.WriteString("False")
		}
	case kvJjUndef:
		// Jinja's default Undefined renders as the empty string.
	case nil:
		sb.WriteString("None")
	default:
		return kvJjErrf(n.pos, "cannot render value of type %T", v)
	}
	return nil
}

func (n *kvJjIf) exec(rt *kvJjRT, sb *strings.Builder) error {
	for i, cond := range n.conds {
		v, err := cond.eval(rt)
		if err != nil {
			return err
		}
		if kvJjTruthy(v) {
			for _, c := range n.bodies[i] {
				if err := c.exec(rt, sb); err != nil {
					return err
				}
			}
			return nil
		}
	}
	for _, c := range n.els {
		if err := c.exec(rt, sb); err != nil {
			return err
		}
	}
	return nil
}

func (n *kvJjFor) exec(rt *kvJjRT, sb *strings.Builder) error {
	seq, err := n.seq.eval(rt)
	if err != nil {
		return err
	}
	items, ok := seq.([]any)
	if !ok {
		return kvJjErrf(n.pos, "for: cannot iterate value of type %T", seq)
	}
	for idx, item := range items {
		frame := map[string]any{
			n.v: item,
			"loop": map[string]any{
				"index0": idx,
				"index":  idx + 1,
				"first":  idx == 0,
				"last":   idx == len(items)-1,
				"length": len(items),
			},
		}
		rt.scopes = append(rt.scopes, frame)
		for _, c := range n.body {
			if err := c.exec(rt, sb); err != nil {
				rt.scopes = rt.scopes[:len(rt.scopes)-1]
				return err
			}
		}
		rt.scopes = rt.scopes[:len(rt.scopes)-1]
	}
	return nil
}

func (n *kvJjSet) exec(rt *kvJjRT, sb *strings.Builder) error {
	v, err := n.e.eval(rt)
	if err != nil {
		return err
	}
	if n.attr == "" {
		rt.set(n.name, v)
		return nil
	}
	cur, ok := rt.lookup(n.name)
	if !ok {
		return kvJjErrf(n.pos, "set: %q is undefined", n.name)
	}
	ns, ok := cur.(*kvJjNS)
	if !ok {
		return kvJjErrf(n.pos, "set: %q is not a namespace", n.name)
	}
	ns.attrs[n.attr] = v
	return nil
}

// ---------------------------------------------------------------------------
// Evaluation.

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
	case string:
		return x != ""
	case []any:
		return len(x) != 0
	case map[string]any:
		return len(x) != 0
	default:
		return true
	}
}

func (e *kvJjLit) eval(rt *kvJjRT) (any, error) { return e.v, nil }

func (e *kvJjVar) eval(rt *kvJjRT) (any, error) {
	if v, ok := rt.lookup(e.name); ok {
		return v, nil
	}
	return kvJjUndef{name: e.name}, nil
}

func (e *kvJjBool) eval(rt *kvJjRT) (any, error) {
	l, err := e.l.eval(rt)
	if err != nil {
		return nil, err
	}
	// Jinja and/or return an operand, not a bool — short-circuit included.
	if e.op == "and" {
		if !kvJjTruthy(l) {
			return l, nil
		}
		return e.r.eval(rt)
	}
	if kvJjTruthy(l) {
		return l, nil
	}
	return e.r.eval(rt)
}

func (e *kvJjNot) eval(rt *kvJjRT) (any, error) {
	v, err := e.e.eval(rt)
	if err != nil {
		return nil, err
	}
	return !kvJjTruthy(v), nil
}

func (e *kvJjCmp) eval(rt *kvJjRT) (any, error) {
	l, err := e.l.eval(rt)
	if err != nil {
		return nil, err
	}
	r, err := e.r.eval(rt)
	if err != nil {
		return nil, err
	}
	if _, u := l.(kvJjUndef); u {
		// Undefined equals nothing and orders after nothing.
		return e.op == "!=", nil
	}
	if _, u := r.(kvJjUndef); u {
		return e.op == "!=", nil
	}
	switch e.op {
	case "==", "!=":
		eq := kvJjEqual(l, r)
		if e.op == "!=" {
			return !eq, nil
		}
		return eq, nil
	}
	li, lok := l.(int)
	ri, rok := r.(int)
	if !lok || !rok {
		return nil, kvJjErrf(e.pos, "cannot order %T against %T", l, r)
	}
	switch e.op {
	case "<":
		return li < ri, nil
	case "<=":
		return li <= ri, nil
	case ">":
		return li > ri, nil
	case ">=":
		return li >= ri, nil
	}
	return nil, kvJjErrf(e.pos, "unknown comparison %q", e.op)
}

func kvJjEqual(l, r any) bool {
	switch lv := l.(type) {
	case string:
		rv, ok := r.(string)
		return ok && lv == rv
	case int:
		rv, ok := r.(int)
		return ok && lv == rv
	case bool:
		rv, ok := r.(bool)
		return ok && lv == rv
	case nil:
		return r == nil
	}
	return false
}

func (e *kvJjIn) eval(rt *kvJjRT) (any, error) {
	l, err := e.l.eval(rt)
	if err != nil {
		return nil, err
	}
	r, err := e.r.eval(rt)
	if err != nil {
		return nil, err
	}
	switch container := r.(type) {
	case string:
		s, ok := l.(string)
		if !ok {
			return nil, kvJjErrf(e.pos, "\"in\" on a string requires a string operand, got %T", l)
		}
		return strings.Contains(container, s), nil
	case []any:
		for _, item := range container {
			if kvJjEqual(l, item) {
				return true, nil
			}
		}
		return false, nil
	}
	return nil, kvJjErrf(e.pos, "\"in\" unsupported for container type %T", r)
}

func (e *kvJjArith) eval(rt *kvJjRT) (any, error) {
	l, err := e.l.eval(rt)
	if err != nil {
		return nil, err
	}
	r, err := e.r.eval(rt)
	if err != nil {
		return nil, err
	}
	if e.op == "~" {
		return kvJjStringify(l) + kvJjStringify(r), nil
	}
	if ls, ok := l.(string); ok {
		if e.op != "+" {
			return nil, kvJjErrf(e.pos, "operator %q unsupported on strings", e.op)
		}
		rs, ok := r.(string)
		if !ok {
			return nil, kvJjErrf(e.pos, "cannot concatenate string with %T", r)
		}
		return ls + rs, nil
	}
	li, lok := l.(int)
	ri, rok := r.(int)
	if !lok || !rok {
		return nil, kvJjErrf(e.pos, "arithmetic on %T and %T", l, r)
	}
	if e.op == "+" {
		return li + ri, nil
	}
	return li - ri, nil
}

func kvJjStringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	case kvJjUndef:
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func (e *kvJjNeg) eval(rt *kvJjRT) (any, error) {
	v, err := e.e.eval(rt)
	if err != nil {
		return nil, err
	}
	i, ok := v.(int)
	if !ok {
		return nil, kvJjErrf(e.pos, "unary minus on %T", v)
	}
	return -i, nil
}

func (e *kvJjAttr) eval(rt *kvJjRT) (any, error) {
	obj, err := e.obj.eval(rt)
	if err != nil {
		return nil, err
	}
	return kvJjGet(obj, e.name, e.pos)
}

func kvJjGet(obj any, name string, pos int) (any, error) {
	switch o := obj.(type) {
	case map[string]any:
		if v, ok := o[name]; ok {
			return v, nil
		}
		return kvJjUndef{name: name}, nil
	case *kvJjNS:
		if v, ok := o.attrs[name]; ok {
			return v, nil
		}
		return kvJjUndef{name: name}, nil
	case kvJjUndef:
		return nil, kvJjErrf(pos, "attribute %q of undefined value %q", name, o.name)
	}
	return nil, kvJjErrf(pos, "attribute %q unsupported on %T", name, obj)
}

func (e *kvJjIndex) eval(rt *kvJjRT) (any, error) {
	obj, err := e.obj.eval(rt)
	if err != nil {
		return nil, err
	}
	idx, err := e.idx.eval(rt)
	if err != nil {
		return nil, err
	}
	if key, ok := idx.(string); ok {
		return kvJjGet(obj, key, e.pos)
	}
	i, ok := idx.(int)
	if !ok {
		return nil, kvJjErrf(e.pos, "subscript of type %T", idx)
	}
	items, ok := obj.([]any)
	if !ok {
		return nil, kvJjErrf(e.pos, "cannot index value of type %T", obj)
	}
	if i < 0 {
		i += len(items)
	}
	if i < 0 || i >= len(items) {
		return nil, kvJjErrf(e.pos, "list index %d out of range (len %d)", i, len(items))
	}
	return items[i], nil
}

func (e *kvJjSlice) eval(rt *kvJjRT) (any, error) {
	obj, err := e.obj.eval(rt)
	if err != nil {
		return nil, err
	}
	items, ok := obj.([]any)
	if !ok {
		return nil, kvJjErrf(e.pos, "cannot slice value of type %T", obj)
	}
	evalPart := func(part kvJjExpr) (int, bool, error) {
		if part == nil {
			return 0, false, nil
		}
		v, err := part.eval(rt)
		if err != nil {
			return 0, false, err
		}
		i, ok := v.(int)
		if !ok {
			return 0, false, kvJjErrf(e.pos, "slice bound of type %T", v)
		}
		return i, true, nil
	}
	step, hasStep, err := evalPart(e.step)
	if err != nil {
		return nil, err
	}
	if !hasStep {
		step = 1
	}
	if step == 0 {
		return nil, kvJjErrf(e.pos, "slice step cannot be zero")
	}
	start, hasStart, err := evalPart(e.start)
	if err != nil {
		return nil, err
	}
	stop, hasStop, err := evalPart(e.stop)
	if err != nil {
		return nil, err
	}
	n := len(items)
	clamp := func(i, lo, hi int) int {
		if i < lo {
			return lo
		}
		if i > hi {
			return hi
		}
		return i
	}
	var out []any
	if step > 0 {
		if !hasStart {
			start = 0
		} else if start < 0 {
			start += n
		}
		if !hasStop {
			stop = n
		} else if stop < 0 {
			stop += n
		}
		start, stop = clamp(start, 0, n), clamp(stop, 0, n)
		for i := start; i < stop; i += step {
			out = append(out, items[i])
		}
	} else {
		if !hasStart {
			start = n - 1
		} else if start < 0 {
			start += n
		}
		if !hasStop {
			stop = -1
		} else {
			if stop < 0 {
				stop += n
			}
			stop = clamp(stop, -1, n-1)
		}
		start = clamp(start, -1, n-1)
		for i := start; i > stop; i += step {
			out = append(out, items[i])
		}
	}
	return out, nil
}

func (e *kvJjMethod) eval(rt *kvJjRT) (any, error) {
	obj, err := e.obj.eval(rt)
	if err != nil {
		return nil, err
	}
	s, ok := obj.(string)
	if !ok {
		return nil, kvJjErrf(e.pos, "method %q unsupported on %T", e.name, obj)
	}
	var args []any
	for _, a := range e.args {
		v, err := a.eval(rt)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	strArg := func(i int) (string, error) {
		if i >= len(args) {
			return "", kvJjErrf(e.pos, "method %q missing argument %d", e.name, i)
		}
		v, ok := args[i].(string)
		if !ok {
			return "", kvJjErrf(e.pos, "method %q argument of type %T", e.name, args[i])
		}
		return v, nil
	}
	switch e.name {
	case "startswith":
		a, err := strArg(0)
		if err != nil {
			return nil, err
		}
		return strings.HasPrefix(s, a), nil
	case "endswith":
		a, err := strArg(0)
		if err != nil {
			return nil, err
		}
		return strings.HasSuffix(s, a), nil
	case "split":
		a, err := strArg(0)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(s, a)
		out := make([]any, len(parts))
		for i, p := range parts {
			out[i] = p
		}
		return out, nil
	case "strip", "lstrip", "rstrip":
		cutset := " \t\r\n\v\f"
		if len(args) > 0 {
			c, err := strArg(0)
			if err != nil {
				return nil, err
			}
			cutset = c
		}
		switch e.name {
		case "strip":
			return strings.Trim(s, cutset), nil
		case "lstrip":
			return strings.TrimLeft(s, cutset), nil
		default:
			return strings.TrimRight(s, cutset), nil
		}
	case "upper":
		return strings.ToUpper(s), nil
	case "lower":
		return strings.ToLower(s), nil
	}
	return nil, kvJjErrf(e.pos, "unsupported method %q", e.name)
}

func (e *kvJjFilter) eval(rt *kvJjRT) (any, error) {
	v, err := e.e.eval(rt)
	if err != nil {
		return nil, err
	}
	switch e.name {
	case "trim":
		s, ok := v.(string)
		if !ok {
			return nil, kvJjErrf(e.pos, "trim filter on %T", v)
		}
		return strings.TrimSpace(s), nil
	case "length":
		switch x := v.(type) {
		case string:
			return len([]rune(x)), nil
		case []any:
			return len(x), nil
		case map[string]any:
			return len(x), nil
		}
		return nil, kvJjErrf(e.pos, "length filter on %T", v)
	case "tojson":
		b, err := json.Marshal(kvJjToJSONable(v))
		if err != nil {
			return nil, kvJjErrf(e.pos, "tojson: %v", err)
		}
		return string(b), nil
	}
	return nil, kvJjErrf(e.pos, "unsupported filter %q", e.name)
}

func kvJjToJSONable(v any) any {
	if _, u := v.(kvJjUndef); u {
		return nil
	}
	return v
}

func (e *kvJjTest) eval(rt *kvJjRT) (any, error) {
	v, err := e.e.eval(rt)
	if err != nil {
		return nil, err
	}
	var res bool
	switch e.name {
	case "defined":
		_, u := v.(kvJjUndef)
		res = !u
	case "undefined":
		_, u := v.(kvJjUndef)
		res = u
	case "string":
		_, res = v.(string)
	case "none":
		res = v == nil
	case "true":
		b, ok := v.(bool)
		res = ok && b
	case "false":
		b, ok := v.(bool)
		res = ok && !b
	default:
		return nil, kvJjErrf(e.pos, "unsupported test %q", e.name)
	}
	if e.negate {
		res = !res
	}
	return res, nil
}

func (e *kvJjNamespaceCall) eval(rt *kvJjRT) (any, error) {
	ns := &kvJjNS{attrs: map[string]any{}}
	for name, expr := range e.kwargs {
		v, err := expr.eval(rt)
		if err != nil {
			return nil, err
		}
		ns.attrs[name] = v
	}
	return ns, nil
}
