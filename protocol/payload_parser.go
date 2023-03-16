package protocol

// parsePayloadRaw parses the key:value pairs from the Event.PayloadBytes field
// and stores them in the Event.Payload map.
//
// Here, too, we're expecting well-formed tokenKey:tokenValue pairs before
// encountering a tokenEOF. Were this a real-world function, we'd expect the
// lexer to emit errors we'd handle here.
func parsePayloadRaw(e *Event) {
	e.Payload = make(map[string]string)

	var (
		key string
		l   = lex(string(e.PayloadBytes))
	)

	for t := range l.tokens {
		switch t.typ {
		case tokenEOF:
			return
		case tokenKey:
			key = t.val
		case tokenValue:
			e.Payload[key] = t.val
		}
	}
}
