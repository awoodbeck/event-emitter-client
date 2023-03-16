package protocol

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_lex(t *testing.T) {
	Convey("Given an input string", t, func() {
		Convey("When lexing the input", func() {
			Convey("It should return expected username and password tokens", func() {
				input := "username:alexander,password:Scribeapple"
				expected := []token{
					{typ: tokenKey, pos: 8, val: "username"},
					{typ: tokenValue, pos: 18, val: "alexander"},
					{typ: tokenKey, pos: 27, val: "password"},
					{typ: tokenValue, pos: 39, val: "Scribeapple"},
					{typ: tokenEOF, pos: 39},
				}

				l := lex(input)
				for _, tok := range expected {
					So(<-l.tokens, ShouldResemble, tok)
				}
			})

			Convey("It should return expected email tokens", func() {
				input := "email:liamwilson186@example.net"
				expected := []token{
					{typ: tokenKey, pos: 5, val: "email"},
					{typ: tokenValue, pos: 31, val: "liamwilson186@example.net"},
					{typ: tokenEOF, pos: 31},
				}

				l := lex(input)
				for _, tok := range expected {
					So(<-l.tokens, ShouldResemble, tok)
				}
			})

			Convey("It should return expected user-agent tokens", func() {
				input := "user-agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14"
				expected := []token{
					{typ: tokenKey, pos: 10, val: "user-agent"},
					{typ: tokenValue, pos: 130, val: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14`},
					{typ: tokenEOF, pos: 130},
				}

				l := lex(input)
				for _, tok := range expected {
					So(<-l.tokens, ShouldResemble, tok)
				}
			})
		})
	})
}
