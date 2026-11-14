// tlscheck: the lab's independent TLS observer (CB-02, oracle rule O-3).
//
// It uses Go's crypto/tls and crypto/x509 only. The scan node's prober shells out to OpenSSL and parses with the
// Python cryptography package, so this client shares no code with the collector. Every command prints one JSON
// object on stdout and exits 0 when it could run (a refused handshake is an observation, not an error).
//
//	tlscheck matrix -addr 10.231.0.17:443 [-sni name]   versions, TLS 1.3 groups, TLS <=1.2 suites Go knows, the
//	                                                      leaf certificate (one handshake per probe, -timeout each)
//	tlscheck hello  -addr ... [-sni name] [-version 1.2] [-group X25519MLKEM768]   one handshake, full detail
//	tlscheck pg     -addr 10.231.0.41:5432 [-version 1.2]  PostgreSQL SSLRequest, then a TLS handshake if 'S'
//	tlscheck mysql  -addr 10.231.0.47:3306 [-version 1.2]  MySQL greeting CLIENT_SSL flag, SSLRequest, TLS handshake
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

var versions = []struct {
	name string
	id   uint16
}{
	{"TLSv1.0", tls.VersionTLS10},
	{"TLSv1.1", tls.VersionTLS11},
	{"TLSv1.2", tls.VersionTLS12},
	{"TLSv1.3", tls.VersionTLS13},
}

// Groups are named as in the IANA "TLS Supported Groups" registry.
var groups = []struct {
	name string
	id   tls.CurveID
}{
	{"x25519", tls.X25519},
	{"secp256r1", tls.CurveP256},
	{"secp384r1", tls.CurveP384},
	{"secp521r1", tls.CurveP521},
	{"X25519MLKEM768", tls.X25519MLKEM768},
}

type certInfo struct {
	SHA256       string   `json:"sha256"`
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	SigAlg       string   `json:"sig_alg"`
	SigAlgOID    string   `json:"sig_alg_oid"`
	PubKeyAlg    string   `json:"pubkey_alg"`
	PubKeyOID    string   `json:"pubkey_oid"`
	KeyBits      int      `json:"key_bits,omitempty"`
	Curve        string   `json:"curve,omitempty"`
	DNSNames     []string `json:"dns_names,omitempty"`
	ParseError   string   `json:"parse_error,omitempty"`
	SelfIssued   bool     `json:"self_issued"`
	SerialNumber string   `json:"serial,omitempty"`
}

type helloResult struct {
	OK          bool       `json:"ok"`
	Error       string     `json:"error,omitempty"`
	Version     string     `json:"version,omitempty"`
	CipherSuite string     `json:"cipher_suite,omitempty"`
	Group       string     `json:"group,omitempty"`
	Certs       []certInfo `json:"certs,omitempty"`
}

type matrixResult struct {
	Tool      string              `json:"tool"`
	Addr      string              `json:"addr"`
	SNI       string              `json:"sni,omitempty"`
	Versions  map[string]bool     `json:"versions"`
	VersionEr map[string]string   `json:"version_errors,omitempty"`
	Groups13  []string            `json:"groups_tls13"`
	Suites    map[string][]string `json:"suites_go"`
	Leaf      *certInfo           `json:"leaf,omitempty"`
	Chain     []certInfo          `json:"chain,omitempty"`
}

var timeout = 5 * time.Second

func toolName() string { return "tlscheck (Go " + runtime.Version() + " crypto/tls)" }

func oidOfSPKI(raw []byte) string {
	var spki struct {
		Alg struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Key asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return ""
	}
	return spki.Alg.OID.String()
}

func oidOfSigAlg(raw []byte) string {
	var c struct {
		TBS    asn1.RawValue
		SigAlg struct {
			OID    asn1.ObjectIdentifier
			Params asn1.RawValue `asn1:"optional"`
		}
		Sig asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &c); err != nil {
		return ""
	}
	return c.SigAlg.OID.String()
}

func describe(raw []byte) certInfo {
	sum := sha256.Sum256(raw)
	ci := certInfo{SHA256: hex.EncodeToString(sum[:]), SigAlgOID: oidOfSigAlg(raw)}
	c, err := x509.ParseCertificate(raw)
	if err != nil {
		ci.ParseError = err.Error()
		return ci
	}
	ci.Subject = c.Subject.String()
	ci.Issuer = c.Issuer.String()
	ci.NotBefore = c.NotBefore.UTC().Format(time.RFC3339)
	ci.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
	ci.SigAlg = c.SignatureAlgorithm.String()
	ci.PubKeyAlg = c.PublicKeyAlgorithm.String()
	ci.PubKeyOID = oidOfSPKI(c.RawSubjectPublicKeyInfo)
	ci.DNSNames = c.DNSNames
	ci.SelfIssued = string(c.RawSubject) == string(c.RawIssuer)
	ci.SerialNumber = c.SerialNumber.Text(16)
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyBits = k.N.BitLen()
	case *ecdsa.PublicKey:
		ci.KeyBits = k.Curve.Params().BitSize
		ci.Curve = k.Curve.Params().Name
	case ed25519.PublicKey:
		ci.KeyBits = 256
		ci.Curve = "Ed25519"
	}
	return ci
}

func groupName(id tls.CurveID) string {
	for _, g := range groups {
		if g.id == id {
			return g.name
		}
	}
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("0x%04x", uint16(id))
}

func baseConfig(sni string) *tls.Config {
	return &tls.Config{
		// The observer must see every certificate, valid or not; nothing here trusts or authenticates a peer.
		InsecureSkipVerify: true,
		ServerName:         sni,
		// The lowest version Go implements: the observer has to see TLS 1.0 servers; each probe pins its own range.
		MinVersion: tls.VersionTLS10,
	}
}

func handshake(conn net.Conn, cfg *tls.Config) helloResult {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, cfg)
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		return helloResult{OK: false, Error: err.Error()}
	}
	st := tc.ConnectionState()
	r := helloResult{OK: true, Version: tls.VersionName(st.Version), CipherSuite: tls.CipherSuiteName(st.CipherSuite),
		Group: groupName(st.CurveID)}
	for _, c := range st.PeerCertificates {
		r.Certs = append(r.Certs, describe(c.Raw))
	}
	return r
}

func dial(addr string) (net.Conn, error) { return net.DialTimeout("tcp", addr, timeout) }

func hello(addr string, cfg *tls.Config) helloResult {
	conn, err := dial(addr)
	if err != nil {
		return helloResult{OK: false, Error: "dial: " + err.Error()}
	}
	return handshake(conn, cfg)
}

func versionCfg(sni string, v uint16) *tls.Config {
	cfg := baseConfig(sni)
	cfg.MinVersion, cfg.MaxVersion = v, v
	if v < tls.VersionTLS13 {
		// Offer every suite Go implements for <= 1.2, the insecure ones included, so a legacy server can answer.
		for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
		}
	}
	return cfg
}

func matrix(addr, sni string) matrixResult {
	m := matrixResult{Tool: toolName(), Addr: addr, SNI: sni, Versions: map[string]bool{}, VersionEr: map[string]string{},
		Suites: map[string][]string{}, Groups13: []string{}}
	for _, v := range versions {
		r := hello(addr, versionCfg(sni, v.id))
		m.Versions[v.name] = r.OK
		if !r.OK {
			m.VersionEr[v.name] = r.Error
		} else if m.Leaf == nil && len(r.Certs) > 0 {
			leaf := r.Certs[0]
			m.Leaf = &leaf
			m.Chain = r.Certs
		}
	}
	if m.Versions["TLSv1.3"] {
		for _, g := range groups {
			cfg := versionCfg(sni, tls.VersionTLS13)
			cfg.CurvePreferences = []tls.CurveID{g.id}
			if r := hello(addr, cfg); r.OK {
				m.Groups13 = append(m.Groups13, g.name)
			}
		}
	}
	for _, v := range versions[:3] {
		if !m.Versions[v.name] {
			continue
		}
		var ok []string
		for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			supported := false
			for _, sv := range s.SupportedVersions {
				if sv == v.id {
					supported = true
				}
			}
			if !supported {
				continue
			}
			cfg := baseConfig(sni)
			cfg.MinVersion, cfg.MaxVersion = v.id, v.id
			cfg.CipherSuites = []uint16{s.ID}
			if r := hello(addr, cfg); r.OK {
				ok = append(ok, s.Name)
			}
		}
		sort.Strings(ok)
		m.Suites[v.name] = ok
	}
	sort.Strings(m.Groups13)
	return m
}

// pg: PostgreSQL protocol 3 SSLRequest (length 8, code 80877103). 'S' = TLS follows, 'N' = refused.
func pg(addr string, cfg *tls.Config) map[string]any {
	out := map[string]any{"tool": toolName(), "addr": addr}
	conn, err := dial(addr)
	if err != nil {
		out["error"] = "dial: " + err.Error()
		return out
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	if _, err := conn.Write(req); err != nil {
		out["error"] = err.Error()
		return out
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		out["error"] = "read: " + err.Error()
		return out
	}
	out["answer"] = string(b)
	out["ssl_supported"] = b[0] == 'S'
	if b[0] != 'S' {
		conn.Close()
		return out
	}
	out["tls"] = handshake(conn, cfg)
	return out
}

const clientSSL = 0x00000800

// mysql: read the v10 greeting, report CLIENT_SSL, and if offered send the 32-byte SSLRequest and run TLS.
func mysql(addr string, cfg *tls.Config) map[string]any {
	out := map[string]any{"tool": toolName(), "addr": addr}
	conn, err := dial(addr)
	if err != nil {
		out["error"] = "dial: " + err.Error()
		return out
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		out["error"] = "read greeting: " + err.Error()
		conn.Close()
		return out
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil || n < 2 || body[0] != 10 {
		out["error"] = "bad greeting"
		conn.Close()
		return out
	}
	i := 1
	end := strings.IndexByte(string(body[i:]), 0)
	if end < 0 {
		out["error"] = "bad greeting"
		conn.Close()
		return out
	}
	out["server_version"] = string(body[i : i+end])
	i += end + 1 + 4 + 8 + 1 // thread id, auth-plugin-data part 1, filler
	if i+2 > len(body) {
		out["error"] = "short greeting"
		conn.Close()
		return out
	}
	capLow := uint32(binary.LittleEndian.Uint16(body[i : i+2]))
	caps := capLow
	if i+2+1+2+2 <= len(body) {
		caps |= uint32(binary.LittleEndian.Uint16(body[i+5:i+7])) << 16
	}
	out["capabilities"] = fmt.Sprintf("0x%08x", caps)
	out["ssl_supported"] = caps&clientSSL != 0
	if caps&clientSSL == 0 {
		conn.Close()
		return out
	}
	// SSLRequest: capability flags (CLIENT_PROTOCOL_41|CLIENT_SSL|CLIENT_SECURE_CONNECTION), max packet, charset, 23 zero bytes.
	req := make([]byte, 4+32)
	req[0], req[3] = 32, 1
	binary.LittleEndian.PutUint32(req[4:8], 0x00000200|clientSSL|0x00008000)
	binary.LittleEndian.PutUint32(req[8:12], 1<<24)
	req[12] = 33
	if _, err := conn.Write(req); err != nil {
		out["error"] = err.Error()
		conn.Close()
		return out
	}
	out["tls"] = handshake(conn, cfg)
	return out
}

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		os.Exit(2)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tlscheck matrix|hello|pg|mysql|version -addr host:port [...]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "", "host:port")
	sni := fs.String("sni", "", "server name to send (none when empty)")
	ver := fs.String("version", "", "pin one version: 1.0, 1.1, 1.2 or 1.3")
	grp := fs.String("group", "", "pin one TLS 1.3 group (IANA name)")
	to := fs.Duration("timeout", timeout, "per-handshake timeout")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	timeout = *to
	switch os.Args[1] {
	case "version":
		emit(map[string]string{"tool": toolName()})
	case "matrix":
		emit(matrix(*addr, *sni))
	case "hello", "pg", "mysql":
		cfg := baseConfig(*sni)
		for _, v := range versions {
			if *ver != "" && strings.TrimPrefix(v.name, "TLSv") == *ver {
				cfg = versionCfg(*sni, v.id)
			}
		}
		if os.Args[1] == "pg" {
			emit(pg(*addr, cfg))
			return
		}
		if os.Args[1] == "mysql" {
			emit(mysql(*addr, cfg))
			return
		}
		if *grp != "" {
			found := false
			for _, g := range groups {
				if g.name == *grp {
					cfg.CurvePreferences = []tls.CurveID{g.id}
					found = true
				}
			}
			if !found {
				emit(helloResult{Error: "unknown group " + *grp})
				return
			}
		}
		emit(hello(*addr, cfg))
	default:
		emit(map[string]string{"error": errors.New("unknown command " + os.Args[1]).Error()})
		os.Exit(2)
	}
}
