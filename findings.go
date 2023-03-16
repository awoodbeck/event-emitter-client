package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/pterm/pterm"
	log "github.com/sirupsen/logrus"

	p "github.com/awoodbeck/event-emitter-client/protocol"
)

// findings is an accounting of the collected events.
type findings struct {
	Events []*p.Event

	ByProtocol map[p.Protocol]*itemOccurrence
	Emails     map[p.Protocol]itemOccurrenceMap
	Passwords  map[p.Protocol]itemOccurrenceMap
	Submitters map[netip.Addr]*itemOccurrence
	UserAgents map[p.Protocol]itemOccurrenceMap
	Usernames  map[p.Protocol]itemOccurrenceMap
}

func (f *findings) populate() {
	f.ByProtocol = make(map[p.Protocol]*itemOccurrence)
	f.Emails = make(map[p.Protocol]itemOccurrenceMap)
	f.Passwords = make(map[p.Protocol]itemOccurrenceMap)
	f.Submitters = make(map[netip.Addr]*itemOccurrence)
	f.UserAgents = make(map[p.Protocol]itemOccurrenceMap)
	f.Usernames = make(map[p.Protocol]itemOccurrenceMap)

	for _, event := range f.Events {
		// ByProtocol
		item := f.ByProtocol[event.Protocol]
		if item == nil {
			item = &itemOccurrence{Events: make([]*p.Event, 0)}
		}
		item.Item = event.Protocol.String()
		item.Occurrence++
		f.ByProtocol[event.Protocol] = item

		// Submitter
		item = f.Submitters[event.IP]
		if item == nil {
			item = &itemOccurrence{Events: make([]*p.Event, 0)}
		}
		item.Events = append(item.Events, event)
		item.Item = event.IP.String()
		item.Occurrence++
		f.Submitters[event.IP] = item

		for k, v := range event.Payload {
			var m itemOccurrenceMap

			switch k {
			case "email":
				m = f.Emails[event.Protocol]
				if m == nil {
					m = make(itemOccurrenceMap)
					f.Emails[event.Protocol] = m
				}
			case "password":
				m = f.Passwords[event.Protocol]
				if m == nil {
					m = make(itemOccurrenceMap)
					f.Passwords[event.Protocol] = m
				}
			case "user-agent":
				m = f.UserAgents[event.Protocol]
				if m == nil {
					m = make(itemOccurrenceMap)
					f.UserAgents[event.Protocol] = m
				}
			case "username":
				m = f.Usernames[event.Protocol]
				if m == nil {
					m = make(itemOccurrenceMap)
					f.Usernames[event.Protocol] = m
				}
			default:
				log.Warnf("unknown event (%s) payload key %q", event.EventUUID.String(), k)
				continue
			}

			item = m[v]
			if item == nil {
				item = new(itemOccurrence)
			}
			item.Item = v
			item.Occurrence++
			m[v] = item
		}
	}
}

func (f *findings) report(ipDetail netip.Addr) (string, error) {
	f.populate()

	var buf bytes.Buffer

	// SSH Top 5 Passwords and Users
	s, err := f.topPasswordsUsers(p.SSH, 5)
	if err != nil {
		return "", err
	}
	buf.WriteString(
		fmt.Sprintf("\u001B[%dmWhat are the top 5 %s passwords and users?\u001B[0m\n\n",
			labelColor, p.SSH.String(),
		),
	)
	buf.WriteString(s)

	// TELNET Top 5 Passwords and Users
	s, err = f.topPasswordsUsers(p.TELNET, 5)
	if err != nil {
		return "", err
	}
	buf.WriteString(
		fmt.Sprintf("\n\n\n\u001B[%dmWhat are the top 5 %s passwords and users?\u001B[0m\n\n",
			labelColor, p.TELNET.String(),
		),
	)
	buf.WriteString(s)

	// HTTP Top 30 User-Agents
	s, err = f.topUserAgents(p.HTTP, 30)
	if err != nil {
		return "", err
	}
	buf.WriteString(
		fmt.Sprintf("\n\n\n\u001B[%dmWhat are the top 30 %s user-agents?\u001B[0m\n\n",
			labelColor, p.HTTP.String(),
		),
	)
	buf.WriteString(s)

	// SMTP Top 20 Emails
	s, err = f.topEmails(p.SMTP, 20)
	if err != nil {
		return "", err
	}
	buf.WriteString(
		fmt.Sprintf("\n\n\n\u001B[%dmWhat are the top 20 %s emails?\u001B[0m\n\n",
			labelColor, p.SMTP.String(),
		),
	)
	buf.WriteString(s)

	// Top 15 Submitters
	s, err = f.topSubmitters(15)
	if err != nil {
		return "", err
	}
	buf.WriteString(
		fmt.Sprintf("\n\n\n\u001B[%dmWho are the top 15 subitters?\u001B[0m\n\n", labelColor),
	)
	buf.WriteString(s)

	// Submitter
	if ipDetail.IsValid() {
		s, err = f.submitter(ipDetail)
		if err != nil {
			return "", err
		}
		buf.WriteString(
			fmt.Sprintf("\n\n\n\u001B[%dmWhat events did %s submit?\u001B[0m\n\n",
				labelColor, ipDetail.String(),
			),
		)
		buf.WriteString(s)
	}

	return buf.String(), nil
}

func (f *findings) submitter(ipDetail netip.Addr) (string, error) {
	d := pterm.TableData{{"#", "Event UUID", "Protocol", "Timestamp"}}

	item, ok := f.Submitters[ipDetail]
	if ok {
		for i, e := range item.Events {
			ts := time.Unix(int64(e.TimeStamp), 0).Format("2006-01-02")
			d = append(d,
				[]string{strconv.Itoa(i + 1), e.EventUUID.String(), e.Protocol.String(), ts},
			)
		}
	} else {
		d = append(d, []string{"", "NO", "EVENTS", "FOUND"})
	}

	return pterm.DefaultTable.WithHasHeader().WithData(d).Srender()
}

func (f *findings) topEmails(proto p.Protocol, count int) (string, error) {
	item, ok := f.ByProtocol[proto]
	if !ok {
		return "", fmt.Errorf("no %s events", proto.String())
	}

	m, ok := f.Emails[proto]
	if !ok {
		return "", fmt.Errorf("no %s emails", proto.String())
	}
	emails := m.top(count)

	d := pterm.TableData{{"#", "Email", "Count"}}
	for i := range emails {
		d = append(d,
			[]string{
				strconv.Itoa(i + 1),
				emails[i].Item,
				strconv.Itoa(emails[i].Occurrence),
			},
		)
	}
	d = append(d,
		[]string{
			"",
			pterm.DefaultTable.HeaderStyle.Sprintf("TOTAL %s EVENTS", proto.String()),
			pterm.DefaultTable.HeaderStyle.Sprintf("%d", item.Occurrence),
		},
	)

	return pterm.DefaultTable.WithHasHeader().WithData(d).Srender()
}

func (f *findings) topPasswordsUsers(proto p.Protocol, count int) (string, error) {
	item, ok := f.ByProtocol[proto]
	if !ok {
		return "", fmt.Errorf("no %s events", proto.String())
	}

	m, ok := f.Passwords[proto]
	if !ok {
		return "", fmt.Errorf("no %s passwords", proto.String())
	}
	passwords := m.top(count)

	m, ok = f.Usernames[proto]
	if !ok {
		return "", fmt.Errorf("no %s users", proto.String())
	}
	usernames := m.top(count)

	d := pterm.TableData{{"#", "Passwords", "Count", "", "Users", "Count"}}
	for i := range passwords {
		d = append(d,
			[]string{
				strconv.Itoa(i + 1),
				passwords[i].Item,
				strconv.Itoa(passwords[i].Occurrence),
				"",
				usernames[i].Item,
				strconv.Itoa(usernames[i].Occurrence),
			},
		)
	}
	d = append(d,
		[]string{
			"", "", "", "",
			pterm.DefaultTable.HeaderStyle.Sprintf("TOTAL %s EVENTS", proto.String()),
			pterm.DefaultTable.HeaderStyle.Sprintf("%d", item.Occurrence),
		},
	)

	return pterm.DefaultTable.WithHasHeader().WithData(d).Srender()
}

func (f *findings) topSubmitters(count int) (string, error) {
	totalEvents := 0
	submitters := make(itemOccurrences, 0, len(f.Submitters))
	for k, v := range f.Submitters {
		submitters = append(submitters, &itemOccurrence{Item: k.String(), Occurrence: v.Occurrence})
		totalEvents += v.Occurrence
	}
	sort.Sort(submitters)

	if len(submitters) < count {
		// Ensure there's at least `count` submitters, even if the last few are
		// empty.
		for j := count - len(submitters); j > 0; j-- {
			submitters = append(submitters, new(itemOccurrence))
		}
	}

	d := pterm.TableData{{"#", "IP Address", "Count"}}
	for i := 0; i < count; i++ {
		d = append(d,
			[]string{
				strconv.Itoa(i + 1),
				submitters[i].Item,
				strconv.Itoa(submitters[i].Occurrence),
			},
		)
	}
	d = append(d,
		[]string{
			"",
			pterm.DefaultTable.HeaderStyle.Sprint("TOTAL EVENTS"),
			pterm.DefaultTable.HeaderStyle.Sprintf("%d", totalEvents),
		},
	)

	return pterm.DefaultTable.WithHasHeader().WithData(d).Srender()
}

func (f *findings) topUserAgents(proto p.Protocol, count int) (string, error) {
	item, ok := f.ByProtocol[proto]
	if !ok {
		return "", fmt.Errorf("no %s events", proto.String())
	}

	m, ok := f.UserAgents[proto]
	if !ok {
		return "", fmt.Errorf("no %s user-agents", proto.String())
	}
	userAgents := m.top(count)

	d := pterm.TableData{{"#", "User-Agents", "Count"}}
	for i := range userAgents {
		d = append(d,
			[]string{
				strconv.Itoa(i + 1),
				userAgents[i].Item,
				strconv.Itoa(userAgents[i].Occurrence),
			},
		)
	}
	d = append(d,
		[]string{
			"",
			pterm.DefaultTable.HeaderStyle.Sprintf("TOTAL %s EVENTS", proto.String()),
			pterm.DefaultTable.HeaderStyle.Sprintf("%d", item.Occurrence),
		},
	)

	return pterm.DefaultTable.WithHasHeader().WithData(d).Srender()
}

type itemOccurrence struct {
	Events     []*p.Event
	Item       string
	Occurrence int
}

type itemOccurrences []*itemOccurrence

func (i itemOccurrences) Len() int { return len(i) }
func (i itemOccurrences) Less(j, k int) bool {
	if i[j].Occurrence == i[k].Occurrence {
		// If the occurrences are the same, sort ascending by the item.
		return i[j].Item < i[k].Item
	}

	// Less is really More in our use case because we want a reverse sort.
	return i[j].Occurrence > i[k].Occurrence
}
func (i itemOccurrences) Swap(j, k int) { i[j], i[k] = i[k], i[j] }

var _ sort.Interface = (*itemOccurrences)(nil)

type itemOccurrenceMap map[string]*itemOccurrence

func (i itemOccurrenceMap) top(count int) itemOccurrences {
	items := itemOccurrences{}

	for _, item := range i {
		items = append(items, item)
	}

	sort.Sort(items)

	if len(items) < count {
		// Ensure there's at least `count` items, even if the last few are empty.
		for j := count - len(items); j > 0; j-- {
			items = append(items, new(itemOccurrence))
		}
	}

	return items[:count]
}
