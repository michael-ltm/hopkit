package ssh

import (
	"errors"
	"net"
	"os"
	"strings"

	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// This deliberately invalid key asks knownhosts for matching records without
// accepting a key or changing the trust database. The library still handles
// hashed hosts, wildcards, negation and nonstandard ports.
type hostKeyAlgorithmProbe struct{}

func (hostKeyAlgorithmProbe) Type() string    { return "" }
func (hostKeyAlgorithmProbe) Marshal() []byte { return nil }
func (hostKeyAlgorithmProbe) Verify([]byte, *gssh.Signature) error {
	return errors.New("host key algorithm probe cannot verify signatures")
}

// Prefer algorithms already trusted for this address, as OpenSSH does. The
// normal callback still verifies the negotiated key, including revocation;
// this is negotiation ordering, never permission to replace a stored key.
func preferredHostKeyAlgorithms(path, address string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	check, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}
	var keyErr *knownhosts.KeyError
	err = check(address, &net.TCPAddr{IP: net.IPv4zero, Port: 22}, hostKeyAlgorithmProbe{})
	if !errors.As(err, &keyErr) {
		return nil, err
	}
	if len(keyErr.Want) == 0 {
		return nil, nil
	}

	preferred := map[string]bool{}
	lines := strings.Split(string(data), "\n")
	all := append(gssh.SupportedAlgorithms().HostKeys, gssh.InsecureAlgorithms().HostKeys...)
	for _, known := range keyErr.Want {
		var fields []string
		if known.Line > 0 && known.Line <= len(lines) {
			fields = strings.Fields(lines[known.Line-1])
		}
		if len(fields) > 0 && fields[0] == "@cert-authority" {
			// A CA may sign a host certificate using a different key algorithm.
			for _, algorithm := range all {
				if strings.Contains(algorithm, "-cert-") {
					preferred[algorithm] = true
				}
			}
			continue
		}
		switch known.Key.Type() {
		case gssh.KeyAlgoRSA:
			preferred[gssh.KeyAlgoRSASHA256] = true
			preferred[gssh.KeyAlgoRSASHA512] = true
			preferred[gssh.KeyAlgoRSA] = true
		case gssh.CertAlgoRSAv01:
			preferred[gssh.CertAlgoRSASHA256v01] = true
			preferred[gssh.CertAlgoRSASHA512v01] = true
			preferred[gssh.CertAlgoRSAv01] = true
		default:
			preferred[known.Key.Type()] = true
		}
	}
	ordered := make([]string, 0, len(all))
	for _, wantPreferred := range []bool{true, false} {
		for _, algorithm := range all {
			if preferred[algorithm] == wantPreferred {
				ordered = append(ordered, algorithm)
			}
		}
	}
	return ordered, nil
}
