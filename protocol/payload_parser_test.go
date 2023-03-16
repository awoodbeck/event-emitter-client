package protocol

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_parsePayload(t *testing.T) {
	Convey("Given an Event with a PayloadBytes value", t, func() {
		Convey("When parsing the payload", func() {
			Convey("It should succeed when parsing a username and a password", func() {
				e := &Event{
					PayloadBytes: []byte("username:alexander,password:Scribeapple"),
				}
				expected := map[string]string{
					"username": "alexander",
					"password": "Scribeapple",
				}

				parsePayloadRaw(e)
				So(e.Payload, ShouldResemble, expected)
			})

			Convey("It should succeed when parsing an email", func() {
				e := &Event{
					PayloadBytes: []byte("email:liamwilson186@example.net"),
				}
				expected := map[string]string{
					"email": "liamwilson186@example.net",
				}

				parsePayloadRaw(e)
				So(e.Payload, ShouldResemble, expected)
			})

			Convey("It should succeed when parsing a user-agent", func() {
				e := &Event{
					PayloadBytes: []byte("user-agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14"),
				}
				expected := map[string]string{
					"user-agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14`,
				}

				parsePayloadRaw(e)
				So(e.Payload, ShouldResemble, expected)
			})
		})
	})
}
