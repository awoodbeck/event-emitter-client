package protocol

import (
	"strings"
	"unicode/utf8"
)

const (
	tokenEOF tokenType = iota + 1
	tokenKey
	tokenValue

	pairSeparator = ","
	separator     = ":"

	eof = -1
)

type tokenType int

type token struct {
	typ tokenType
	pos int
	val string
}

type stateFn func(*lexer) stateFn

// lexer returns relevant tokens from the input string. The input is
// well-formed for this specific assignment, so various syntactical checks
// (e.g., abrupt EOF, keys with no values, etc.) have been omitted for brevity.
//
// This is based on Rob Pike's Lexical Scanning talk:
// https://www.youtube.com/watch?v=HxaD_trXwRE
type lexer struct {
	input  string
	start  int
	pos    int
	width  int
	state  stateFn
	tokens chan token
}

func (l *lexer) acceptUntil(c string) {
	for r := l.next(); r != eof && !strings.ContainsRune(c, r); {
		r = l.next()
	}

	l.backup()
}

func (l *lexer) acceptUntilEOF() {
	for r := l.next(); r != eof; {
		r = l.next()
	}
}

func (l *lexer) backup() { l.pos -= l.width }

func (l *lexer) emit(t tokenType) {
	l.tokens <- token{
		typ: t,
		pos: l.pos,
		val: l.input[l.start:l.pos],
	}
	l.start = l.pos
}

// first returns the first character in chars encountered in the input from the
// current position. If none of the characters are found, an empty string is
// returned.
func (l *lexer) first(chars ...string) string {
	var (
		firstIndex  = -1
		firstString string
	)

	for _, c := range chars {
		if i := l.index(c); i >= 0 && (firstIndex < 0 || i < firstIndex) {
			firstIndex = i
			firstString = c
		}
	}

	return firstString
}

func (l *lexer) ignore()            { l.start = l.pos }
func (l *lexer) index(c string) int { return strings.Index(l.input[l.pos:], c) }
func (l *lexer) isEOF() bool        { return l.pos >= len(l.input) }

func (l *lexer) next() rune {
	if l.isEOF() {
		l.width = 0

		return eof
	}

	r, w := utf8.DecodeRuneInString(l.input[l.pos:])
	l.width = w
	l.pos += l.width

	return r
}

func (l *lexer) run() {
	for l.state = lexKey; l.state != nil; {
		l.state = l.state(l)
	}

	close(l.tokens)
}

func lex(input string) *lexer {
	l := &lexer{
		input:  input,
		tokens: make(chan token),
	}

	go l.run()

	return l
}

func lexKey(l *lexer) stateFn {
	l.acceptUntil(separator)
	l.emit(tokenKey)

	return lexSeparator
}

func lexPairSeparator(l *lexer) stateFn {
	l.pos += len(pairSeparator)
	l.ignore()

	return lexKey
}

func lexSeparator(l *lexer) stateFn {
	l.pos += len(separator)
	l.ignore()

	return lexValue
}

func lexValue(l *lexer) stateFn {
	var (
		tok       string
		nextState stateFn
	)

	if l.index(separator) >= 0 && l.first(pairSeparator, separator) == pairSeparator {
		// There are multiple key:value pairs in the input. Lex the key:value
		// pair separator.
		tok = pairSeparator
		nextState = lexPairSeparator
	}

	if tok == "" {
		l.acceptUntilEOF()
	} else {
		l.acceptUntil(tok)
	}

	l.emit(tokenValue)

	if l.isEOF() {
		l.emit(tokenEOF)

		return nil
	}

	return nextState
}
