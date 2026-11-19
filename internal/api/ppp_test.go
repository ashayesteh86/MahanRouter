package api

import "testing"

func TestParseAccelSessions(t *testing.T) {
	out := ` ifname | username |     ip     | type | state  | uptime-raw | calling-sid | rx-bytes-raw | tx-bytes-raw
--------+----------+------------+------+--------+------------+-------------+--------------+--------------
 ppps0  | ali      | 10.80.0.2  | l2tp | active | 75         | 10.99.0.10  | 1234         | 5678
        |          |            | pptp | start  | 2          | 10.99.0.11  | 0            | 0
`
	s := parseAccelSessions(out)
	if len(s) != 2 {
		t.Fatalf("got %d sessions: %+v", len(s), s)
	}
	if s[0].Ifname != "ppps0" || s[0].Username != "ali" || s[0].Uptime != 75 || s[0].RxBytes != 1234 || s[0].From != "10.99.0.10" {
		t.Errorf("first: %+v", s[0])
	}
	if s[1].State != "start" || s[1].Ifname != "" {
		t.Errorf("second: %+v", s[1])
	}
	if !sessIfRe.MatchString("ppps12") || sessIfRe.MatchString("ppps1;rm") || sessIfRe.MatchString("eth0") {
		t.Error("session name check")
	}
}
