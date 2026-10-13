package fingerprint

import (
	"encoding/json"
	"strconv"
	"strings"
)

// UnmarshalJSON accepts the field spellings that show up in real scanner
// exports, not just the canonical {"ip","port","banner"} triple:
//
//	ip      : ip | ip_address | host | address | addr
//	port    : port | port_number | dst_port          (number or string)
//	banner  : banner | data | response | raw | payload | service_banner
//
// Unknown extra fields are ignored, so richer scan records (timestamps, ASN,
// tls metadata, ...) can be posted unchanged.
func (in *Input) UnmarshalJSON(b []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		// Tolerate a bare banner string.
		var s string
		if err2 := json.Unmarshal(b, &s); err2 == nil {
			in.Banner = s
			return nil
		}
		return err
	}

	pick := func(keys ...string) (json.RawMessage, bool) {
		for _, k := range keys {
			if v, ok := obj[k]; ok && len(v) > 0 && string(v) != "null" {
				return v, true
			}
		}
		return nil, false
	}

	if v, ok := pick("ip", "ip_address", "host", "address", "addr", "hostname"); ok {
		in.IP = asString(v)
	}
	if v, ok := pick("port", "port_number", "dst_port", "dstport"); ok {
		in.Port = asInt(v)
	}
	if v, ok := pick("banner", "data", "response", "raw", "raw_banner", "banner_text", "service_banner", "payload"); ok {
		in.Banner = asString(v)
	}
	return nil
}

func asString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return strings.Trim(string(raw), `"`)
}

func asInt(raw json.RawMessage) int {
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	if v, err := strconv.Atoi(strings.Trim(asString(raw), `"`)); err == nil {
		return v
	}
	return 0
}
