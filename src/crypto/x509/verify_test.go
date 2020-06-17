// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"
)

type verifyTest struct {
	name          string
	leaf          string
	intermediates []string
	roots         []string
	currentTime   int64
	dnsName       string
	systemSkip    bool
	systemLax     bool
	keyUsages     []ExtKeyUsage
	ignoreCN      bool

	errorCallback  func(*testing.T, error)
	expectedChains [][]string
}

var verifyTests = []verifyTest{
	{
		name:          "Valid",
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.google.com",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
	},
	{
		name:          "MixedCase",
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "WwW.GooGLE.coM",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
	},
	{
		name:          "HostnameMismatch",
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.example.com",

		errorCallback: expectHostnameError("certificate is valid for"),
	},
	{
		name:          "IPMissing",
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "1.2.3.4",

		errorCallback: expectHostnameError("doesn't contain any IP SANs"),
	},
	{
		name:          "Expired",
		leaf:          googleLeaf,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1,
		dnsName:       "www.example.com",

		errorCallback: expectExpired,
	},
	{
		name:        "MissingIntermediate",
		leaf:        googleLeaf,
		roots:       []string{geoTrustRoot},
		currentTime: 1395785200,
		dnsName:     "www.google.com",

		// Skip when using systemVerify, since Windows
		// *will* find the missing intermediate cert.
		systemSkip:    true,
		errorCallback: expectAuthorityUnknown,
	},
	{
		name:          "RootInIntermediates",
		leaf:          googleLeaf,
		intermediates: []string{geoTrustRoot, giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.google.com",

		expectedChains: [][]string{
			{"Google", "Google Internet Authority", "GeoTrust"},
		},
		// CAPI doesn't build the chain with the duplicated GeoTrust
		// entry so the results don't match.
		systemLax: true,
	},
	{
		name:          "dnssec-exp",
		leaf:          dnssecExpLeaf,
		intermediates: []string{startComIntermediate},
		roots:         []string{startComRoot},
		currentTime:   1302726541,

		// The StartCom root is not trusted by Windows when the default
		// ServerAuth EKU is requested.
		systemSkip: true,

		expectedChains: [][]string{
			{"dnssec-exp", "StartCom Class 1", "StartCom Certification Authority"},
		},
	},
	{
		name:          "dnssec-exp/AnyEKU",
		leaf:          dnssecExpLeaf,
		intermediates: []string{startComIntermediate},
		roots:         []string{startComRoot},
		currentTime:   1302726541,
		keyUsages:     []ExtKeyUsage{ExtKeyUsageAny},

		expectedChains: [][]string{
			{"dnssec-exp", "StartCom Class 1", "StartCom Certification Authority"},
		},
	},
	{
		name:          "dnssec-exp/RootInIntermediates",
		leaf:          dnssecExpLeaf,
		intermediates: []string{startComIntermediate, startComRoot},
		roots:         []string{startComRoot},
		currentTime:   1302726541,
		systemSkip:    true, // see dnssec-exp test

		expectedChains: [][]string{
			{"dnssec-exp", "StartCom Class 1", "StartCom Certification Authority"},
		},
	},
	{
		name:          "InvalidHash",
		leaf:          googleLeafWithInvalidHash,
		intermediates: []string{giag2Intermediate},
		roots:         []string{geoTrustRoot},
		currentTime:   1395785200,
		dnsName:       "www.google.com",

		// The specific error message may not occur when using system
		// verification.
		systemLax:     true,
		errorCallback: expectHashError,
	},
	// EKULeaf tests use an unconstrained chain leading to a leaf certificate
	// with an E-mail Protection EKU but not a Server Auth one, checking that
	// the EKUs on the leaf are enforced.
	{
		name:          "EKULeaf",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		currentTime:   1594673418,

		errorCallback: expectUsageError,
	},
	{
		name:          "EKULeafExplicit",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		currentTime:   1594673418,
		keyUsages:     []ExtKeyUsage{ExtKeyUsageServerAuth},

		errorCallback: expectUsageError,
	},
	{
		name:          "EKULeafValid",
		leaf:          smimeLeaf,
		intermediates: []string{smimeIntermediate},
		roots:         []string{smimeRoot},
		currentTime:   1594673418,
		keyUsages:     []ExtKeyUsage{ExtKeyUsageEmailProtection},

		expectedChains: [][]string{
			{"CORPORATIVO FICTICIO ACTIVO", "EAEko Herri Administrazioen CA - CA AAPP Vascas (2)", "IZENPE S.A."},
		},
	},
	{
		name:          "SGCIntermediate",
		leaf:          megaLeaf,
		intermediates: []string{comodoIntermediate1},
		roots:         []string{comodoRoot},
		currentTime:   1360431182,

		// CryptoAPI can find alternative validation paths.
		systemLax: true,
		expectedChains: [][]string{
			{"mega.co.nz", "EssentialSSL CA", "COMODO Certification Authority"},
		},
	},
	{
		// Check that a name constrained intermediate works even when
		// it lists multiple constraints.
		name:          "MultipleConstraints",
		leaf:          nameConstraintsLeaf,
		intermediates: []string{nameConstraintsIntermediate1, nameConstraintsIntermediate2},
		roots:         []string{globalSignRoot},
		currentTime:   1382387896,
		dnsName:       "secure.iddl.vt.edu",

		expectedChains: [][]string{
			{
				"Technology-enhanced Learning and Online Strategies",
				"Virginia Tech Global Qualified Server CA",
				"Trusted Root CA G2",
				"GlobalSign Root CA",
			},
		},
	},
	{
		// Check that SHA-384 intermediates (which are popping up)
		// work.
		name:          "SHA-384",
		leaf:          moipLeafCert,
		intermediates: []string{comodoIntermediateSHA384, comodoRSAAuthority},
		roots:         []string{addTrustRoot},
		currentTime:   1397502195,
		dnsName:       "api.moip.com.br",

		// CryptoAPI can find alternative validation paths.
		systemLax: true,

		expectedChains: [][]string{
			{
				"api.moip.com.br",
				"COMODO RSA Extended Validation Secure Server CA",
				"COMODO RSA Certification Authority",
				"AddTrust External CA Root",
			},
		},
	},
	{
		// Putting a certificate as a root directly should work as a
		// way of saying “exactly this”.
		name:        "LeafInRoots",
		leaf:        selfSigned,
		roots:       []string{selfSigned},
		currentTime: 1471624472,
		dnsName:     "foo.example",
		systemSkip:  true, // does not chain to a system root

		expectedChains: [][]string{
			{"Acme Co"},
		},
	},
	{
		// Putting a certificate as a root directly should not skip
		// other checks however.
		name:        "LeafInRootsInvalid",
		leaf:        selfSigned,
		roots:       []string{selfSigned},
		currentTime: 1471624472,
		dnsName:     "notfoo.example",
		systemSkip:  true, // does not chain to a system root

		errorCallback: expectHostnameError("certificate is valid for"),
	},
	{
		// An X.509 v1 certificate should not be accepted as an
		// intermediate.
		name:          "X509v1Intermediate",
		leaf:          x509v1TestLeaf,
		intermediates: []string{x509v1TestIntermediate},
		roots:         []string{x509v1TestRoot},
		currentTime:   1481753183,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectNotAuthorizedError,
	},
	{
		// If any SAN extension is present (even one without any DNS
		// names), the CN should be ignored.
		name:        "IgnoreCNWithSANs",
		leaf:        ignoreCNWithSANLeaf,
		dnsName:     "foo.example.com",
		roots:       []string{ignoreCNWithSANRoot},
		currentTime: 1486684488,
		systemSkip:  true, // does not chain to a system root

		errorCallback: expectHostnameError("certificate is not valid for any names"),
	},
	{
		// Test that excluded names are respected.
		name:          "ExcludedNames",
		leaf:          excludedNamesLeaf,
		dnsName:       "bender.local",
		intermediates: []string{excludedNamesIntermediate},
		roots:         []string{excludedNamesRoot},
		currentTime:   1486684488,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test that unknown critical extensions in a leaf cause a
		// verify error.
		name:          "CriticalExtLeaf",
		leaf:          criticalExtLeafWithExt,
		dnsName:       "example.com",
		intermediates: []string{criticalExtIntermediate},
		roots:         []string{criticalExtRoot},
		currentTime:   1486684488,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectUnhandledCriticalExtension,
	},
	{
		// Test that unknown critical extensions in an intermediate
		// cause a verify error.
		name:          "CriticalExtIntermediate",
		leaf:          criticalExtLeaf,
		dnsName:       "example.com",
		intermediates: []string{criticalExtIntermediateWithExt},
		roots:         []string{criticalExtRoot},
		currentTime:   1486684488,
		systemSkip:    true, // does not chain to a system root

		errorCallback: expectUnhandledCriticalExtension,
	},
	{
		// Test that invalid CN are ignored.
		name:        "InvalidCN",
		leaf:        invalidCNWithoutSAN,
		dnsName:     "foo,invalid",
		roots:       []string{invalidCNRoot},
		currentTime: 1540000000,
		systemSkip:  true, // does not chain to a system root

		errorCallback: expectHostnameError("Common Name is not a valid hostname"),
	},
	{
		// Test that valid CN are respected.
		name:        "ValidCN",
		leaf:        validCNWithoutSAN,
		dnsName:     "foo.example.com",
		roots:       []string{invalidCNRoot},
		currentTime: 1540000000,
		systemSkip:  true, // does not chain to a system root

		expectedChains: [][]string{
			{"foo.example.com", "Test root"},
		},
	},
	// Replicate CN tests with ignoreCN = true
	{
		name:        "IgnoreCNWithSANs/ignoreCN",
		leaf:        ignoreCNWithSANLeaf,
		dnsName:     "foo.example.com",
		roots:       []string{ignoreCNWithSANRoot},
		currentTime: 1486684488,
		systemSkip:  true, // does not chain to a system root
		ignoreCN:    true,

		errorCallback: expectHostnameError("certificate is not valid for any names"),
	},
	{
		name:        "InvalidCN/ignoreCN",
		leaf:        invalidCNWithoutSAN,
		dnsName:     "foo,invalid",
		roots:       []string{invalidCNRoot},
		currentTime: 1540000000,
		systemSkip:  true, // does not chain to a system root
		ignoreCN:    true,

		errorCallback: expectHostnameError("certificate is not valid for any names"),
	},
	{
		name:        "ValidCN/ignoreCN",
		leaf:        validCNWithoutSAN,
		dnsName:     "foo.example.com",
		roots:       []string{invalidCNRoot},
		currentTime: 1540000000,
		systemSkip:  true, // does not chain to a system root
		ignoreCN:    true,

		errorCallback: expectHostnameError("certificate relies on legacy Common Name field"),
	},
	{
		// A certificate with an AKID should still chain to a parent without SKID.
		// See Issue 30079.
		name:        "AKIDNoSKID",
		leaf:        leafWithAKID,
		roots:       []string{rootWithoutSKID},
		currentTime: 1550000000,
		dnsName:     "example",
		systemSkip:  true, // does not chain to a system root

		expectedChains: [][]string{
			{"Acme LLC", "Acme Co"},
		},
	},
	{
		// When there are two parents, one with a incorrect subject but matching SKID
		// and one with a correct subject but missing SKID, the latter should be
		// considered as a possible parent.
		leaf:        leafMatchingAKIDMatchingIssuer,
		roots:       []string{rootMatchingSKIDMismatchingSubject, rootMismatchingSKIDMatchingSubject},
		currentTime: 1550000000,
		dnsName:     "example",
		systemSkip:  true,

		expectedChains: [][]string{
			{"Leaf", "Root B"},
		},
	},
	{
		// Test if permitted dirname constraint works.
		leaf:          dirNameConstraintLeafCA_permitted_ok,
		intermediates: []string{dirNameConstraintSubCA_permitted_ok},
		roots:         []string{dirNameConstraintRootCA_permitted_ok},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if permitted RDN match dirname constraint.
		leaf:          dirNameConstraintLeafCA_permitted_dirname_multirdn,
		intermediates: []string{dirNameConstraintSubCA_permitted_dirname_multirdn},
		roots:         []string{dirNameConstraintRootCA_permitted_dirname_multirdn},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if RootCA dirname constraint violation is ignored.
		leaf:          dirNameConstraintLeafCA_notpermitted_rootca,
		intermediates: []string{dirNameConstraintSubCA_notpermitted_rootca},
		roots:         []string{dirNameConstraintRootCA_notpermitted_rootca},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if SubCA dirname constraint violation (ST missing) fails.
		leaf:          dirNameConstraintLeafCA_notpermitted_subca_missing,
		intermediates: []string{dirNameConstraintSubCA_notpermitted_subca_missing},
		roots:         []string{dirNameConstraintRootCA_notpermitted_subca_missing},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if SubCA dirname constraint violation (ST changed) fails.
		leaf:          dirNameConstraintLeafCA_notpermitted_subca_changed,
		intermediates: []string{dirNameConstraintSubCA_notpermitted_subca_changed},
		roots:         []string{dirNameConstraintRootCA_notpermitted_subca_changed},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if leaf dirname constraint violation (ST missing) fails.
		leaf:          dirNameConstraintLeafCA_notpermitted_leaf_missing,
		intermediates: []string{dirNameConstraintSubCA_notpermitted_leaf_missing},
		roots:         []string{dirNameConstraintRootCA_notpermitted_leaf_missing},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if leaf dirname constraint violation (ST changed) fails.
		leaf:          dirNameConstraintLeafCA_notpermitted_leaf_changed,
		intermediates: []string{dirNameConstraintSubCA_notpermitted_leaf_changed},
		roots:         []string{dirNameConstraintRootCA_notpermitted_leaf_changed},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if excluded dirname works.
		leaf:          dirNameConstraintLeafCA_excluded_ok,
		intermediates: []string{dirNameConstraintSubCA_excluded_ok},
		roots:         []string{dirNameConstraintRootCA_excluded_ok},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if RootCA using excluded dirname is ignored.
		leaf:          dirNameConstraintLeafCA_excluded_rootca,
		intermediates: []string{dirNameConstraintSubCA_excluded_rootca},
		roots:         []string{dirNameConstraintRootCA_excluded_rootca},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if SubCA using excluded dirname fails.
		leaf:          dirNameConstraintLeafCA_excluded_subca,
		intermediates: []string{dirNameConstraintSubCA_excluded_subca},
		roots:         []string{dirNameConstraintRootCA_excluded_subca},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if leaf using excluded dirname fails.
		leaf:          dirNameConstraintLeafCA_excluded_leaf,
		intermediates: []string{dirNameConstraintSubCA_excluded_leaf},
		roots:         []string{dirNameConstraintRootCA_excluded_leaf},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if permitted and excluded dirname works together.
		leaf:          dirNameConstraintLeafCA_permitted_excluded_OK,
		intermediates: []string{dirNameConstraintSubCA_permitted_excluded_OK},
		roots:         []string{dirNameConstraintRootCA_permitted_excluded_OK},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if RootCA using dirname both in excluded and permitted fails.
		leaf:          dirNameConstraintLeafCA_permitted_excluded_rootca,
		intermediates: []string{dirNameConstraintSubCA_permitted_excluded_rootca},
		roots:         []string{dirNameConstraintRootCA_permitted_excluded_rootca},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if SubCA using dirname both in excluded and permitted fails.
		leaf:          dirNameConstraintLeafCA_permitted_excluded_subca,
		intermediates: []string{dirNameConstraintSubCA_permitted_excluded_subca},
		roots:         []string{dirNameConstraintRootCA_permitted_excluded_subca},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if leaf using dirname both in excluded and permitted fails.
		leaf:          dirNameConstraintLeafCA_permitted_excluded_leaf,
		intermediates: []string{dirNameConstraintSubCA_permitted_excluded_leaf},
		roots:         []string{dirNameConstraintRootCA_permitted_excluded_leaf},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if SubCA can restrict a constraint.
		leaf:          dirNameConstraintLeafCA_subca_restr_ok,
		intermediates: []string{dirNameConstraintSubCA_subca_restr_ok},
		roots:         []string{dirNameConstraintRootCA_subca_restr_ok},
		currentTime:   1600000000,
		systemSkip:    true,

		expectedChains: [][]string{
			{"Leaf", "SubCA", "RootCA"},
		},
	},
	{
		// Test if SubCA can restrict a constraint.
		leaf:          dirNameConstraintLeafCA_subca_restr_fail,
		intermediates: []string{dirNameConstraintSubCA_subca_restr_fail},
		roots:         []string{dirNameConstraintRootCA_subca_restr_fail},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
	{
		// Test if SubCA can relax a constraint.
		leaf:          dirNameConstraintLeafCA_subca_relax_fail,
		intermediates: []string{dirNameConstraintSubCA_subca_relax_fail},
		roots:         []string{dirNameConstraintRootCA_subca_relax_fail},
		currentTime:   1600000000,
		systemSkip:    true,

		errorCallback: expectNameConstraintsError,
	},
}

func expectHostnameError(msg string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if _, ok := err.(HostnameError); !ok {
			t.Fatalf("error was not a HostnameError: %v", err)
		}
		if !strings.Contains(err.Error(), msg) {
			t.Fatalf("HostnameError did not contain %q: %v", msg, err)
		}
	}
}

func expectExpired(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != Expired {
		t.Fatalf("error was not Expired: %v", err)
	}
}

func expectUsageError(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != IncompatibleUsage {
		t.Fatalf("error was not IncompatibleUsage: %v", err)
	}
}

func expectAuthorityUnknown(t *testing.T, err error) {
	e, ok := err.(UnknownAuthorityError)
	if !ok {
		t.Fatalf("error was not UnknownAuthorityError: %v", err)
	}
	if e.Cert == nil {
		t.Fatalf("error was UnknownAuthorityError, but missing Cert: %v", err)
	}
}

func expectHashError(t *testing.T, err error) {
	if err == nil {
		t.Fatalf("no error resulted from invalid hash")
	}
	if expected := "algorithm unimplemented"; !strings.Contains(err.Error(), expected) {
		t.Fatalf("error resulting from invalid hash didn't contain '%s', rather it was: %v", expected, err)
	}
}

func expectNameConstraintsError(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != CANotAuthorizedForThisName {
		t.Fatalf("error was not a CANotAuthorizedForThisName: %v", err)
	}
}

func expectNotAuthorizedError(t *testing.T, err error) {
	if inval, ok := err.(CertificateInvalidError); !ok || inval.Reason != NotAuthorizedToSign {
		t.Fatalf("error was not a NotAuthorizedToSign: %v", err)
	}
}

func expectUnhandledCriticalExtension(t *testing.T, err error) {
	if _, ok := err.(UnhandledCriticalExtension); !ok {
		t.Fatalf("error was not an UnhandledCriticalExtension: %v", err)
	}
}

func certificateFromPEM(pemBytes string) (*Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return ParseCertificate(block.Bytes)
}

func testVerify(t *testing.T, test verifyTest, useSystemRoots bool) {
	defer func(savedIgnoreCN bool) { ignoreCN = savedIgnoreCN }(ignoreCN)

	ignoreCN = test.ignoreCN
	opts := VerifyOptions{
		Intermediates: NewCertPool(),
		DNSName:       test.dnsName,
		CurrentTime:   time.Unix(test.currentTime, 0),
		KeyUsages:     test.keyUsages,
	}

	if !useSystemRoots {
		opts.Roots = NewCertPool()
		for j, root := range test.roots {
			ok := opts.Roots.AppendCertsFromPEM([]byte(root))
			if !ok {
				t.Fatalf("failed to parse root #%d", j)
			}
		}
	}

	for j, intermediate := range test.intermediates {
		ok := opts.Intermediates.AppendCertsFromPEM([]byte(intermediate))
		if !ok {
			t.Fatalf("failed to parse intermediate #%d", j)
		}
	}

	leaf, err := certificateFromPEM(test.leaf)
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
	}

	chains, err := leaf.Verify(opts)

	if test.errorCallback == nil && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if test.errorCallback != nil {
		if useSystemRoots && test.systemLax {
			if err == nil {
				t.Fatalf("expected error")
			}
		} else {
			test.errorCallback(t, err)
		}
	}

	if len(chains) != len(test.expectedChains) {
		t.Errorf("wanted %d chains, got %d", len(test.expectedChains), len(chains))
	}

	// We check that each returned chain matches a chain from
	// expectedChains but an entry in expectedChains can't match
	// two chains.
	seenChains := make([]bool, len(chains))
NextOutputChain:
	for _, chain := range chains {
	TryNextExpected:
		for j, expectedChain := range test.expectedChains {
			if seenChains[j] {
				continue
			}
			if len(chain) != len(expectedChain) {
				continue
			}
			for k, cert := range chain {
				if !strings.Contains(nameToKey(&cert.Subject), expectedChain[k]) {
					continue TryNextExpected
				}
			}
			// we matched
			seenChains[j] = true
			continue NextOutputChain
		}
		t.Errorf("no expected chain matched %s", chainToDebugString(chain))
	}
}

func TestGoVerify(t *testing.T) {
	for _, test := range verifyTests {
		t.Run(test.name, func(t *testing.T) {
			testVerify(t, test, false)
		})
	}
}

func TestSystemVerify(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("skipping verify test using system APIs on %q", runtime.GOOS)
	}

	for _, test := range verifyTests {
		t.Run(test.name, func(t *testing.T) {
			if test.systemSkip {
				t.SkipNow()
			}
			testVerify(t, test, true)
		})
	}
}

func chainToDebugString(chain []*Certificate) string {
	var chainStr string
	for _, cert := range chain {
		if len(chainStr) > 0 {
			chainStr += " -> "
		}
		chainStr += nameToKey(&cert.Subject)
	}
	return chainStr
}

func nameToKey(name *pkix.Name) string {
	return strings.Join(name.Country, ",") + "/" + strings.Join(name.Organization, ",") + "/" + strings.Join(name.OrganizationalUnit, ",") + "/" + name.CommonName
}

const geoTrustRoot = `-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
-----END CERTIFICATE-----`

const giag2Intermediate = `-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

const googleLeaf = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----`

// googleLeafWithInvalidHash is the same as googleLeaf, but the signature
// algorithm in the certificate contains a nonsense OID.
const googleLeafWithInvalidHash = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAWAFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQFgBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----`

const dnssecExpLeaf = `-----BEGIN CERTIFICATE-----
MIIGzTCCBbWgAwIBAgIDAdD6MA0GCSqGSIb3DQEBBQUAMIGMMQswCQYDVQQGEwJJ
TDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0
YWwgQ2VydGlmaWNhdGUgU2lnbmluZzE4MDYGA1UEAxMvU3RhcnRDb20gQ2xhc3Mg
MSBQcmltYXJ5IEludGVybWVkaWF0ZSBTZXJ2ZXIgQ0EwHhcNMTAwNzA0MTQ1MjQ1
WhcNMTEwNzA1MTA1NzA0WjCBwTEgMB4GA1UEDRMXMjIxMTM3LWxpOWE5dHhJRzZM
NnNyVFMxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVQZXJzb25hIE5vdCBWYWxpZGF0
ZWQxKTAnBgNVBAsTIFN0YXJ0Q29tIEZyZWUgQ2VydGlmaWNhdGUgTWVtYmVyMRsw
GQYDVQQDExJ3d3cuZG5zc2VjLWV4cC5vcmcxKDAmBgkqhkiG9w0BCQEWGWhvc3Rt
YXN0ZXJAZG5zc2VjLWV4cC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDEdF/22vaxrPbqpgVYMWi+alfpzBctpbfLBdPGuqOazJdCT0NbWcK8/+B4
X6OlSOURNIlwLzhkmwVsWdVv6dVSaN7d4yI/fJkvgfDB9+au+iBJb6Pcz8ULBfe6
D8HVvqKdORp6INzHz71z0sghxrQ0EAEkoWAZLh+kcn2ZHdcmZaBNUfjmGbyU6PRt
RjdqoP+owIaC1aktBN7zl4uO7cRjlYFdusINrh2kPP02KAx2W84xjxX1uyj6oS6e
7eBfvcwe8czW/N1rbE0CoR7h9+HnIrjnVG9RhBiZEiw3mUmF++Up26+4KTdRKbu3
+BL4yMpfd66z0+zzqu+HkvyLpFn5AgMBAAGjggL/MIIC+zAJBgNVHRMEAjAAMAsG
A1UdDwQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUy04I5guM
drzfh2JQaXhgV86+4jUwHwYDVR0jBBgwFoAU60I00Jiwq5/0G2sI98xkLu8OLEUw
LQYDVR0RBCYwJIISd3d3LmRuc3NlYy1leHAub3Jngg5kbnNzZWMtZXhwLm9yZzCC
AUIGA1UdIASCATkwggE1MIIBMQYLKwYBBAGBtTcBAgIwggEgMC4GCCsGAQUFBwIB
FiJodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9wb2xpY3kucGRmMDQGCCsGAQUFBwIB
FihodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9pbnRlcm1lZGlhdGUucGRmMIG3Bggr
BgEFBQcCAjCBqjAUFg1TdGFydENvbSBMdGQuMAMCAQEagZFMaW1pdGVkIExpYWJp
bGl0eSwgc2VlIHNlY3Rpb24gKkxlZ2FsIExpbWl0YXRpb25zKiBvZiB0aGUgU3Rh
cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUG9saWN5IGF2YWlsYWJsZSBh
dCBodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9wb2xpY3kucGRmMGEGA1UdHwRaMFgw
KqAooCaGJGh0dHA6Ly93d3cuc3RhcnRzc2wuY29tL2NydDEtY3JsLmNybDAqoCig
JoYkaHR0cDovL2NybC5zdGFydHNzbC5jb20vY3J0MS1jcmwuY3JsMIGOBggrBgEF
BQcBAQSBgTB/MDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5zdGFydHNzbC5jb20v
c3ViL2NsYXNzMS9zZXJ2ZXIvY2EwQgYIKwYBBQUHMAKGNmh0dHA6Ly93d3cuc3Rh
cnRzc2wuY29tL2NlcnRzL3N1Yi5jbGFzczEuc2VydmVyLmNhLmNydDAjBgNVHRIE
HDAahhhodHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS8wDQYJKoZIhvcNAQEFBQADggEB
ACXj6SB59KRJPenn6gUdGEqcta97U769SATyiQ87i9er64qLwvIGLMa3o2Rcgl2Y
kghUeyLdN/EXyFBYA8L8uvZREPoc7EZukpT/ZDLXy9i2S0jkOxvF2fD/XLbcjGjM
iEYG1/6ASw0ri9C0k4oDDoJLCoeH9++yqF7SFCCMcDkJqiAGXNb4euDpa8vCCtEQ
CSS+ObZbfkreRt3cNCf5LfCXe9OsTnCfc8Cuq81c0oLaG+SmaLUQNBuToq8e9/Zm
+b+/a3RVjxmkV5OCcGVBxsXNDn54Q6wsdw0TBMcjwoEndzpLS7yWgFbbkq5ZiGpw
Qibb2+CfKuQ+WFV1GkVQmVA=
-----END CERTIFICATE-----`

const startComIntermediate = `-----BEGIN CERTIFICATE-----
MIIGNDCCBBygAwIBAgIBGDANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEW
MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg
Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMDcxMDI0MjA1NDE3WhcNMTcxMDI0MjA1NDE3WjCB
jDELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xKzApBgNVBAsT
IlNlY3VyZSBEaWdpdGFsIENlcnRpZmljYXRlIFNpZ25pbmcxODA2BgNVBAMTL1N0
YXJ0Q29tIENsYXNzIDEgUHJpbWFyeSBJbnRlcm1lZGlhdGUgU2VydmVyIENBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtonGrO8JUngHrJJj0PREGBiE
gFYfka7hh/oyULTTRwbw5gdfcA4Q9x3AzhA2NIVaD5Ksg8asWFI/ujjo/OenJOJA
pgh2wJJuniptTT9uYSAK21ne0n1jsz5G/vohURjXzTCm7QduO3CHtPn66+6CPAVv
kvek3AowHpNz/gfK11+AnSJYUq4G2ouHI2mw5CrY6oPSvfNx23BaKA+vWjhwRRI/
ME3NO68X5Q/LoKldSKqxYVDLNM08XMML6BDAjJvwAwNi/rJsPnIO7hxDKslIDlc5
xDEhyBDBLIf+VJVSH1I8MRKbf+fAoKVZ1eKPPvDVqOHXcDGpxLPPr21TLwb0pwID
AQABo4IBrTCCAakwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD
VR0OBBYEFOtCNNCYsKuf9BtrCPfMZC7vDixFMB8GA1UdIwQYMBaAFE4L7xqkQFul
F2mHMMo0aEPQQa7yMGYGCCsGAQUFBwEBBFowWDAnBggrBgEFBQcwAYYbaHR0cDov
L29jc3Auc3RhcnRzc2wuY29tL2NhMC0GCCsGAQUFBzAChiFodHRwOi8vd3d3LnN0
YXJ0c3NsLmNvbS9zZnNjYS5jcnQwWwYDVR0fBFQwUjAnoCWgI4YhaHR0cDovL3d3
dy5zdGFydHNzbC5jb20vc2ZzY2EuY3JsMCegJaAjhiFodHRwOi8vY3JsLnN0YXJ0
c3NsLmNvbS9zZnNjYS5jcmwwgYAGA1UdIAR5MHcwdQYLKwYBBAGBtTcBAgEwZjAu
BggrBgEFBQcCARYiaHR0cDovL3d3dy5zdGFydHNzbC5jb20vcG9saWN5LnBkZjA0
BggrBgEFBQcCARYoaHR0cDovL3d3dy5zdGFydHNzbC5jb20vaW50ZXJtZWRpYXRl
LnBkZjANBgkqhkiG9w0BAQUFAAOCAgEAIQlJPqWIbuALi0jaMU2P91ZXouHTYlfp
tVbzhUV1O+VQHwSL5qBaPucAroXQ+/8gA2TLrQLhxpFy+KNN1t7ozD+hiqLjfDen
xk+PNdb01m4Ge90h2c9W/8swIkn+iQTzheWq8ecf6HWQTd35RvdCNPdFWAwRDYSw
xtpdPvkBnufh2lWVvnQce/xNFE+sflVHfXv0pQ1JHpXo9xLBzP92piVH0PN1Nb6X
t1gW66pceG/sUzCv6gRNzKkC4/C2BBL2MLERPZBOVmTX3DxDX3M570uvh+v2/miI
RHLq0gfGabDBoYvvF0nXYbFFSF87ICHpW7LM9NfpMfULFWE7epTj69m8f5SuauNi
YpaoZHy4h/OZMn6SolK+u/hlz8nyMPyLwcKmltdfieFcNID1j0cHL7SRv7Gifl9L
WtBbnySGBVFaaQNlQ0lxxeBvlDRr9hvYqbBMflPrj0jfyjO1SPo2ShpTpjMM0InN
SRXNiTE8kMBy12VLUjWKRhFEuT2OKGWmPnmeXAhEKa2wNREuIU640ucQPl2Eg7PD
wuTSxv0JS3QJ3fGz0xk+gA2iCxnwOOfFwq/iI9th4p1cbiCJSS4jarJiwUW0n6+L
p/EiO/h94pDQehn7Skzj0n1fSoMD7SfWI55rjbRZotnvbIIp3XUZPD9MEI3vu3Un
0q6Dp6jOW6c=
-----END CERTIFICATE-----`

const startComRoot = `-----BEGIN CERTIFICATE-----
MIIHyTCCBbGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJJTDEW
MBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERpZ2l0YWwg
Q2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwHhcNMDYwOTE3MTk0NjM2WhcNMzYwOTE3MTk0NjM2WjB9
MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMi
U2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3Rh
cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQDBiNsJvGxGfHiflXu1M5DycmLWwTYgIiRezul38kMKogZk
pMyONvg45iPwbm2xPN1yo4UcodM9tDMr0y+v/uqwQVlntsQGfQqedIXWeUyAN3rf
OQVSWff0G0ZDpNKFhdLDcfN1YjS6LIp/Ho/u7TTQEceWzVI9ujPW3U3eCztKS5/C
Ji/6tRYccjV3yjxd5srhJosaNnZcAdt0FCX+7bWgiA/deMotHweXMAEtcnn6RtYT
Kqi5pquDSR3l8u/d5AGOGAqPY1MWhWKpDhk6zLVmpsJrdAfkK+F2PrRt2PZE4XNi
HzvEvqBTViVsUQn3qqvKv3b9bZvzndu/PWa8DFaqr5hIlTpL36dYUNk4dalb6kMM
Av+Z6+hsTXBbKWWc3apdzK8BMewM69KN6Oqce+Zu9ydmDBpI125C4z/eIT574Q1w
+2OqqGwaVLRcJXrJosmLFqa7LH4XXgVNWG4SHQHuEhANxjJ/GP/89PrNbpHoNkm+
Gkhpi8KWTRoSsmkXwQqQ1vp5Iki/untp+HDH+no32NgN0nZPV/+Qt+OR0t3vwmC3
Zzrd/qqc8NSLf3Iizsafl7b4r4qgEKjZ+xjGtrVcUjyJthkqcwEKDwOzEmDyei+B
26Nu/yYwl/WL3YlXtq09s68rxbd2AvCl1iuahhQqcvbjM4xdCUsT37uMdBNSSwID
AQABo4ICUjCCAk4wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAa4wHQYDVR0OBBYE
FE4L7xqkQFulF2mHMMo0aEPQQa7yMGQGA1UdHwRdMFswLKAqoCiGJmh0dHA6Ly9j
ZXJ0LnN0YXJ0Y29tLm9yZy9zZnNjYS1jcmwuY3JsMCugKaAnhiVodHRwOi8vY3Js
LnN0YXJ0Y29tLm9yZy9zZnNjYS1jcmwuY3JsMIIBXQYDVR0gBIIBVDCCAVAwggFM
BgsrBgEEAYG1NwEBATCCATswLwYIKwYBBQUHAgEWI2h0dHA6Ly9jZXJ0LnN0YXJ0
Y29tLm9yZy9wb2xpY3kucGRmMDUGCCsGAQUFBwIBFilodHRwOi8vY2VydC5zdGFy
dGNvbS5vcmcvaW50ZXJtZWRpYXRlLnBkZjCB0AYIKwYBBQUHAgIwgcMwJxYgU3Rh
cnQgQ29tbWVyY2lhbCAoU3RhcnRDb20pIEx0ZC4wAwIBARqBl0xpbWl0ZWQgTGlh
YmlsaXR5LCByZWFkIHRoZSBzZWN0aW9uICpMZWdhbCBMaW1pdGF0aW9ucyogb2Yg
dGhlIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFBvbGljeSBhdmFp
bGFibGUgYXQgaHR0cDovL2NlcnQuc3RhcnRjb20ub3JnL3BvbGljeS5wZGYwEQYJ
YIZIAYb4QgEBBAQDAgAHMDgGCWCGSAGG+EIBDQQrFilTdGFydENvbSBGcmVlIFNT
TCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTANBgkqhkiG9w0BAQUFAAOCAgEAFmyZ
9GYMNPXQhV59CuzaEE44HF7fpiUFS5Eyweg78T3dRAlbB0mKKctmArexmvclmAk8
jhvh3TaHK0u7aNM5Zj2gJsfyOZEdUauCe37Vzlrk4gNXcGmXCPleWKYK34wGmkUW
FjgKXlf2Ysd6AgXmvB618p70qSmD+LIU424oh0TDkBreOKk8rENNZEXO3SipXPJz
ewT4F+irsfMuXGRuczE6Eri8sxHkfY+BUZo7jYn0TZNmezwD7dOaHZrzZVD1oNB1
ny+v8OqCQ5j4aZyJecRDjkZy42Q2Eq/3JR44iZB3fsNrarnDy0RLrHiQi+fHLB5L
EUTINFInzQpdn4XBidUaePKVEFMy3YCEZnXZtWgo+2EuvoSoOMCZEoalHmdkrQYu
L6lwhceWD3yJZfWOQ1QOq92lgDmUYMA0yZZwLKMS9R9Ie70cfmu3nZD0Ijuu+Pwq
yvqCUqDvr0tVk+vBtfAii6w0TiYiBKGHLHVKt+V9E9e4DGTANtLJL4YSjCMJwRuC
O3NJo2pXh5Tl1njFmUNj403gdy3hZZlyaQQaRwnmDwFWJPsfvw55qVguucQJAX6V
um0ABj6y6koQOdjQK/W/7HW/lwLFCRsI3FU34oH7N4RDYiDK51ZLZer+bMEkkySh
NOsF/5oirpt9P/FlUQqmMGqz9IgcgA38corog14=
-----END CERTIFICATE-----`

const smimeLeaf = `-----BEGIN CERTIFICATE-----
MIIIPDCCBiSgAwIBAgIQaMDxFS0pOMxZZeOBxoTJtjANBgkqhkiG9w0BAQsFADCB
nTELMAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMTowOAYDVQQLDDFB
WlogWml1cnRhZ2lyaSBwdWJsaWtvYSAtIENlcnRpZmljYWRvIHB1YmxpY28gU0NB
MTwwOgYDVQQDDDNFQUVrbyBIZXJyaSBBZG1pbmlzdHJhemlvZW4gQ0EgLSBDQSBB
QVBQIFZhc2NhcyAoMikwHhcNMTcwNzEyMDg1MzIxWhcNMjEwNzEyMDg1MzIxWjCC
AQwxDzANBgNVBAoMBklaRU5QRTE4MDYGA1UECwwvWml1cnRhZ2lyaSBrb3Jwb3Jh
dGlib2EtQ2VydGlmaWNhZG8gY29ycG9yYXRpdm8xQzBBBgNVBAsMOkNvbmRpY2lv
bmVzIGRlIHVzbyBlbiB3d3cuaXplbnBlLmNvbSBub2xhIGVyYWJpbGkgamFraXRl
a28xFzAVBgNVBC4TDi1kbmkgOTk5OTk5ODlaMSQwIgYDVQQDDBtDT1JQT1JBVElW
TyBGSUNUSUNJTyBBQ1RJVk8xFDASBgNVBCoMC0NPUlBPUkFUSVZPMREwDwYDVQQE
DAhGSUNUSUNJTzESMBAGA1UEBRMJOTk5OTk5ODlaMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwVOMwUDfBtsH0XuxYnb+v/L774jMH8valX7RPH8cl2Lb
SiqSo0RchW2RGA2d1yuYHlpChC9jGmt0X/g66/E/+q2hUJlfJtqVDJFwtFYV4u2S
yzA3J36V4PRkPQrKxAsbzZriFXAF10XgiHQz9aVeMMJ9GBhmh9+DK8Tm4cMF6i8l
+AuC35KdngPF1x0ealTYrYZplpEJFO7CiW42aLi6vQkDR2R7nmZA4AT69teqBWsK
0DZ93/f0G/3+vnWwNTBF0lB6dIXoaz8OMSyHLqGnmmAtMrzbjAr/O/WWgbB/BqhR
qjJQ7Ui16cuDldXaWQ/rkMzsxmsAox0UF+zdQNvXUQIDAQABo4IDBDCCAwAwgccG
A1UdEgSBvzCBvIYVaHR0cDovL3d3dy5pemVucGUuY29tgQ9pbmZvQGl6ZW5wZS5j
b22kgZEwgY4xRzBFBgNVBAoMPklaRU5QRSBTLkEuIC0gQ0lGIEEwMTMzNzI2MC1S
TWVyYy5WaXRvcmlhLUdhc3RlaXogVDEwNTUgRjYyIFM4MUMwQQYDVQQJDDpBdmRh
IGRlbCBNZWRpdGVycmFuZW8gRXRvcmJpZGVhIDE0IC0gMDEwMTAgVml0b3JpYS1H
YXN0ZWl6MB4GA1UdEQQXMBWBE2ZpY3RpY2lvQGl6ZW5wZS5ldXMwDgYDVR0PAQH/
BAQDAgXgMCkGA1UdJQQiMCAGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNxQC
AjAdBgNVHQ4EFgQUyeoOD4cgcljKY0JvrNuX2waFQLAwHwYDVR0jBBgwFoAUwKlK
90clh/+8taaJzoLSRqiJ66MwggEnBgNVHSAEggEeMIIBGjCCARYGCisGAQQB8zkB
AQEwggEGMDMGCCsGAQUFBwIBFidodHRwOi8vd3d3Lml6ZW5wZS5jb20vcnBhc2Nh
Y29ycG9yYXRpdm8wgc4GCCsGAQUFBwICMIHBGoG+Wml1cnRhZ2lyaWEgRXVza2Fs
IEF1dG9ub21pYSBFcmtpZGVnb2tvIHNla3RvcmUgcHVibGlrb2tvIGVyYWt1bmRl
ZW4gYmFybmUtc2FyZWV0YW4gYmFrYXJyaWsgZXJhYmlsIGRhaXRla2UuIFVzbyBy
ZXN0cmluZ2lkbyBhbCBhbWJpdG8gZGUgcmVkZXMgaW50ZXJuYXMgZGUgRW50aWRh
ZGVzIGRlbCBTZWN0b3IgUHVibGljbyBWYXNjbzAyBggrBgEFBQcBAQQmMCQwIgYI
KwYBBQUHMAGGFmh0dHA6Ly9vY3NwLml6ZW5wZS5jb20wOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5pemVucGUuY29tL2NnaS1iaW4vY3JsaW50ZXJuYTIwDQYJ
KoZIhvcNAQELBQADggIBAIy5PQ+UZlCRq6ig43vpHwlwuD9daAYeejV0Q+ZbgWAE
GtO0kT/ytw95ZEJMNiMw3fYfPRlh27ThqiT0VDXZJDlzmn7JZd6QFcdXkCsiuv4+
ZoXAg/QwnA3SGUUO9aVaXyuOIIuvOfb9MzoGp9xk23SMV3eiLAaLMLqwB5DTfBdt
BGI7L1MnGJBv8RfP/TL67aJ5bgq2ri4S8vGHtXSjcZ0+rCEOLJtmDNMnTZxancg3
/H5edeNd+n6Z48LO+JHRxQufbC4mVNxVLMIP9EkGUejlq4E4w6zb5NwCQczJbSWL
i31rk2orsNsDlyaLGsWZp3JSNX6RmodU4KAUPor4jUJuUhrrm3Spb73gKlV/gcIw
bCE7mML1Kss3x1ySaXsis6SZtLpGWKkW2iguPWPs0ydV6RPhmsCxieMwPPIJ87vS
5IejfgyBae7RSuAIHyNFy4uI5xwvwUFf6OZ7az8qtW7ImFOgng3Ds+W9k1S2CNTx
d0cnKTfA6IpjGo8EeHcxnIXT8NPImWaRj0qqonvYady7ci6U4m3lkNSdXNn1afgw
mYust+gxVtOZs1gk2MUCgJ1V1X+g7r/Cg7viIn6TLkLrpS1kS1hvMqkl9M+7XqPo
Qd95nJKOkusQpy99X4dF/lfbYAQnnjnqh3DLD2gvYObXFaAYFaiBKTiMTV2X72F+
-----END CERTIFICATE-----`

const smimeIntermediate = `-----BEGIN CERTIFICATE-----
MIIHNzCCBSGgAwIBAgIQJMXIqlZvjuhMvqcFXOFkpDALBgkqhkiG9w0BAQswODEL
MAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMRMwEQYDVQQDDApJemVu
cGUuY29tMB4XDTEwMTAyMDA4MjMzM1oXDTM3MTIxMjIzMDAwMFowgZ0xCzAJBgNV
BAYTAkVTMRQwEgYDVQQKDAtJWkVOUEUgUy5BLjE6MDgGA1UECwwxQVpaIFppdXJ0
YWdpcmkgcHVibGlrb2EgLSBDZXJ0aWZpY2FkbyBwdWJsaWNvIFNDQTE8MDoGA1UE
AwwzRUFFa28gSGVycmkgQWRtaW5pc3RyYXppb2VuIENBIC0gQ0EgQUFQUCBWYXNj
YXMgKDIpMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoIM7nEdI0N1h
rR5T4xuV/usKDoMIasaiKvfLhbwxaNtTt+a7W/6wV5bv3svQFIy3sUXjjdzV1nG2
To2wo/YSPQiOt8exWvOapvL21ogiof+kelWnXFjWaKJI/vThHYLgIYEMj/y4HdtU
ojI646rZwqsb4YGAopwgmkDfUh5jOhV2IcYE3TgJAYWVkj6jku9PLaIsHiarAHjD
PY8dig8a4SRv0gm5Yk7FXLmW1d14oxQBDeHZ7zOEXfpafxdEDO2SNaRJjpkh8XRr
PGqkg2y1Q3gT6b4537jz+StyDIJ3omylmlJsGCwqT7p8mEqjGJ5kC5I2VnjXKuNn
soShc72khWZVUJiJo5SGuAkNE2ZXqltBVm5Jv6QweQKsX6bkcMc4IZok4a+hx8FM
8IBpGf/I94pU6HzGXqCyc1d46drJgDY9mXa+6YDAJFl3xeXOOW2iGCfwXqhiCrKL
MYvyMZzqF3QH5q4nb3ZnehYvraeMFXJXDn+Utqp8vd2r7ShfQJz01KtM4hgKdgSg
jtW+shkVVN5ng/fPN85ovfAH2BHXFfHmQn4zKsYnLitpwYM/7S1HxlT61cdQ7Nnk
3LZTYEgAoOmEmdheklT40WAYakksXGM5VrzG7x9S7s1Tm+Vb5LSThdHC8bxxwyTb
KsDRDNJ84N9fPDO6qHnzaL2upQ43PycCAwEAAaOCAdkwggHVMIHHBgNVHREEgb8w
gbyGFWh0dHA6Ly93d3cuaXplbnBlLmNvbYEPaW5mb0BpemVucGUuY29tpIGRMIGO
MUcwRQYDVQQKDD5JWkVOUEUgUy5BLiAtIENJRiBBMDEzMzcyNjAtUk1lcmMuVml0
b3JpYS1HYXN0ZWl6IFQxMDU1IEY2MiBTODFDMEEGA1UECQw6QXZkYSBkZWwgTWVk
aXRlcnJhbmVvIEV0b3JiaWRlYSAxNCAtIDAxMDEwIFZpdG9yaWEtR2FzdGVpejAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUwKlK90cl
h/+8taaJzoLSRqiJ66MwHwYDVR0jBBgwFoAUHRxlDqjyJXu0kc/ksbHmvVV0bAUw
OgYDVR0gBDMwMTAvBgRVHSAAMCcwJQYIKwYBBQUHAgEWGWh0dHA6Ly93d3cuaXpl
bnBlLmNvbS9jcHMwNwYIKwYBBQUHAQEEKzApMCcGCCsGAQUFBzABhhtodHRwOi8v
b2NzcC5pemVucGUuY29tOjgwOTQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
bC5pemVucGUuY29tL2NnaS1iaW4vYXJsMjALBgkqhkiG9w0BAQsDggIBAMbjc3HM
3DG9ubWPkzsF0QsktukpujbTTcGk4h20G7SPRy1DiiTxrRzdAMWGjZioOP3/fKCS
M539qH0M+gsySNie+iKlbSZJUyE635T1tKw+G7bDUapjlH1xyv55NC5I6wCXGC6E
3TEP5B/E7dZD0s9E4lS511ubVZivFgOzMYo1DO96diny/N/V1enaTCpRl1qH1OyL
xUYTijV4ph2gL6exwuG7pxfRcVNHYlrRaXWfTz3F6NBKyULxrI3P/y6JAtN1GqT4
VF/+vMygx22n0DufGepBwTQz6/rr1ulSZ+eMnuJiTXgh/BzQnkUsXTb8mHII25iR
0oYF2qAsk6ecWbLiDpkHKIDHmML21MZE13MS8NSvTHoqJO4LyAmDe6SaeNHtrPlK
b6mzE1BN2ug+ZaX8wLA5IMPFaf0jKhb/Cxu8INsxjt00brsErCc9ip1VNaH0M4bi
1tGxfiew2436FaeyUxW7Pl6G5GgkNbuUc7QIoRy06DdU/U38BxW3uyJMY60zwHvS
FlKAn0OvYp4niKhAJwaBVN3kowmJuOU5Rid+TUnfyxbJ9cttSgzaF3hP/N4zgMEM
5tikXUskeckt8LUK96EH0QyssavAMECUEb/xrupyRdYWwjQGvNLq6T5+fViDGyOw
k+lzD44wofy8paAy9uC9Owae0zMEzhcsyRm7
-----END CERTIFICATE-----`

const smimeRoot = `-----BEGIN CERTIFICATE-----
MIIF8TCCA9mgAwIBAgIQALC3WhZIX7/hy/WL1xnmfTANBgkqhkiG9w0BAQsFADA4
MQswCQYDVQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xEzARBgNVBAMMCkl6
ZW5wZS5jb20wHhcNMDcxMjEzMTMwODI4WhcNMzcxMjEzMDgyNzI1WjA4MQswCQYD
VQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xEzARBgNVBAMMCkl6ZW5wZS5j
b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDJ03rKDx6sp4boFmVq
scIbRTJxldn+EFvMr+eleQGPicPK8lVx93e+d5TzcqQsRNiekpsUOqHnJJAKClaO
xdgmlOHZSOEtPtoKct2jmRXagaKH9HtuJneJWK3W6wyyQXpzbm3benhB6QiIEn6H
LmYRY2xU+zydcsC8Lv/Ct90NduM61/e0aL6i9eOBbsFGb12N4E3GVFWJGjMxCrFX
uaOKmMPsOzTFlUFpfnXCPCDFYbpRR6AgkJOhkEvzTnyFRVSa0QUmQbC1TR0zvsQD
yCV8wXDbO/QJLVQnSKwv4cSsPsjLkkxTOTcj7NMB+eAJRE1NZMDhDVqHIrytG6P+
JrUV86f8hBnp7KGItERphIPzidF0BqnMC9bC3ieFUCbKF7jJeodWLBoBHmy+E60Q
rLUk9TiRodZL2vG70t5HtfG8gfZZa88ZU+mNFctKy6lvROUbQc/hhqfK0GqfvEyN
BjNaooXlkDWgYlwWTvDjovoDGrQscbNYLN57C9saD+veIR8GdwYDsMnvmfzAuU8L
hij+0rnq49qlw0dpEuDb8PYZi+17cNcC1u2HGCgsBCRMd+RIihrGO5rUD8r6ddIB
QFqNeb+Lz0vPqhbBleStTIo+F5HUsWLlguWABKQDfo2/2n+iD5dPDNMN+9fR5XJ+
HMh3/1uaD7euBUbl8agW7EekFwIDAQABo4H2MIHzMIGwBgNVHREEgagwgaWBD2lu
Zm9AaXplbnBlLmNvbaSBkTCBjjFHMEUGA1UECgw+SVpFTlBFIFMuQS4gLSBDSUYg
QTAxMzM3MjYwLVJNZXJjLlZpdG9yaWEtR2FzdGVpeiBUMTA1NSBGNjIgUzgxQzBB
BgNVBAkMOkF2ZGEgZGVsIE1lZGl0ZXJyYW5lbyBFdG9yYmlkZWEgMTQgLSAwMTAx
MCBWaXRvcmlhLUdhc3RlaXowDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFB0cZQ6o8iV7tJHP5LGx5r1VdGwFMA0GCSqGSIb3DQEBCwUA
A4ICAQB4pgwWSp9MiDrAyw6lFn2fuUhfGI8NYjb2zRlrrKvV9pF9rnHzP7MOeIWb
laQnIUdCSnxIOvVFfLMMjlF4rJUT3sb9fbgakEyrkgPH7UIBzg/YsfqikuFgba56
awmqxinuaElnMIAkejEWOVt+8Rwu3WwJrfIxwYJOubv5vr8qhT/AQKM6WfxZSzwo
JNu0FXWuDYi6LnPAvViH5ULy617uHjAimcs30cQhbIHsvm0m5hzkQiCeR7Csg1lw
LDXWrzY0tM07+DKo7+N4ifuNRSzanLh+QBxh5z6ikixL8s36mLYp//Pye6kfLqCT
VyvehQP5aTfLnnhqBbTFMXiJ7HqnheG5ezzevh55hM6fcA5ZwjUukCox2eRFekGk
LhObNA5me0mrZJfQRsN5nXJQY6aYWwa9SG3YOYNw6DXwBdGqvOPbyALqfP2C2sJb
UjWumDqtujWTI6cfSN01RpiyEGjkpTHCClguGYEQyVB1/OpaFs4R1+7vUIgtYf8/
QnMFlEPVjjxOAToZpR9GTnfQXeWBIiGH/pR9hNiTrdZoQ0iy2+tzJOeRf1SktoA+
naM8THLCV8Sg1Mw4J87VBp6iSNnpn86CcDaTmjvfliHjWbcM2pE38P1ZWrOZyGls
QyYBNWNgVYkDOnXYukrZVP/u3oDYLdE41V4tC5h9Pmzb/CaIxw==
-----END CERTIFICATE-----`

var megaLeaf = `-----BEGIN CERTIFICATE-----
MIIFOjCCBCKgAwIBAgIQWYE8Dup170kZ+k11Lg51OjANBgkqhkiG9w0BAQUFADBy
MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEYMBYGA1UE
AxMPRXNzZW50aWFsU1NMIENBMB4XDTEyMTIxNDAwMDAwMFoXDTE0MTIxNDIzNTk1
OVowfzEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMS4wLAYDVQQL
EyVIb3N0ZWQgYnkgSW5zdHJhIENvcnBvcmF0aW9uIFB0eS4gTFREMRUwEwYDVQQL
EwxFc3NlbnRpYWxTU0wxEzARBgNVBAMTCm1lZ2EuY28ubnowggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDcxMCClae8BQIaJHBUIVttlLvhbK4XhXPk3RQ3
G5XA6tLZMBQ33l3F9knYJ0YErXtr8IdfYoulRQFmKFMJl9GtWyg4cGQi2Rcr5VN5
S5dA1vu4oyJBxE9fPELcK6Yz1vqaf+n6za+mYTiQYKggVdS8/s8hmNuXP9Zk1pIn
+q0pGsf8NAcSHMJgLqPQrTDw+zae4V03DvcYfNKjuno88d2226ld7MAmQZ7uRNsI
/CnkdelVs+akZsXf0szefSqMJlf08SY32t2jj4Ra7RApVYxOftD9nij/aLfuqOU6
ow6IgIcIG2ZvXLZwK87c5fxL7UAsTTV+M1sVv8jA33V2oKLhAgMBAAGjggG9MIIB
uTAfBgNVHSMEGDAWgBTay+qtWwhdzP/8JlTOSeVVxjj0+DAdBgNVHQ4EFgQUmP9l
6zhyrZ06Qj4zogt+6LKFk4AwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAw
NAYDVR0lBC0wKwYIKwYBBQUHAwEGCCsGAQUFBwMCBgorBgEEAYI3CgMDBglghkgB
hvhCBAEwTwYDVR0gBEgwRjA6BgsrBgEEAbIxAQICBzArMCkGCCsGAQUFBwIBFh1o
dHRwczovL3NlY3VyZS5jb21vZG8uY29tL0NQUzAIBgZngQwBAgEwOwYDVR0fBDQw
MjAwoC6gLIYqaHR0cDovL2NybC5jb21vZG9jYS5jb20vRXNzZW50aWFsU1NMQ0Eu
Y3JsMG4GCCsGAQUFBwEBBGIwYDA4BggrBgEFBQcwAoYsaHR0cDovL2NydC5jb21v
ZG9jYS5jb20vRXNzZW50aWFsU1NMQ0FfMi5jcnQwJAYIKwYBBQUHMAGGGGh0dHA6
Ly9vY3NwLmNvbW9kb2NhLmNvbTAlBgNVHREEHjAcggptZWdhLmNvLm56gg53d3cu
bWVnYS5jby5uejANBgkqhkiG9w0BAQUFAAOCAQEAcYhrsPSvDuwihMOh0ZmRpbOE
Gw6LqKgLNTmaYUPQhzi2cyIjhUhNvugXQQlP5f0lp5j8cixmArafg1dTn4kQGgD3
ivtuhBTgKO1VYB/VRoAt6Lmswg3YqyiS7JiLDZxjoV7KoS5xdiaINfHDUaBBY4ZH
j2BUlPniNBjCqXe/HndUTVUewlxbVps9FyCmH+C4o9DWzdGBzDpCkcmo5nM+cp7q
ZhTIFTvZfo3zGuBoyu8BzuopCJcFRm3cRiXkpI7iOMUIixO1szkJS6WpL1sKdT73
UXp08U0LBqoqG130FbzEJBBV3ixbvY6BWMHoCWuaoF12KJnC5kHt2RoWAAgMXA==
-----END CERTIFICATE-----`

var comodoIntermediate1 = `-----BEGIN CERTIFICATE-----
MIIFAzCCA+ugAwIBAgIQGLLLuqME8aAPwfLzJkYqSjANBgkqhkiG9w0BAQUFADCB
gTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxJzAlBgNV
BAMTHkNPTU9ETyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjEyMDEwMDAw
MDBaFw0xOTEyMzEyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVh
dGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9E
TyBDQSBMaW1pdGVkMRgwFgYDVQQDEw9Fc3NlbnRpYWxTU0wgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt8AiwcsargxIxF3CJhakgEtSYau2A1NHf
5I5ZLdOWIY120j8YC0YZYwvHIPPlC92AGvFaoL0dds23Izp0XmEbdaqb1IX04XiR
0y3hr/yYLgbSeT1awB8hLRyuIVPGOqchfr7tZ291HRqfalsGs2rjsQuqag7nbWzD
ypWMN84hHzWQfdvaGlyoiBSyD8gSIF/F03/o4Tjg27z5H6Gq1huQByH6RSRQXScq
oChBRVt9vKCiL6qbfltTxfEFFld+Edc7tNkBdtzffRDPUanlOPJ7FAB1WfnwWdsX
Pvev5gItpHnBXaIcw5rIp6gLSApqLn8tl2X2xQScRMiZln5+pN0vAgMBAAGjggGD
MIIBfzAfBgNVHSMEGDAWgBQLWOWLxkwVN6RAqTCpIb5HNlpW/zAdBgNVHQ4EFgQU
2svqrVsIXcz//CZUzknlVcY49PgwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQI
MAYBAf8CAQAwIAYDVR0lBBkwFwYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBMD4GA1Ud
IAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21v
ZG8uY29tL0NQUzBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLmNvbW9kb2Nh
LmNvbS9DT01PRE9DZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBsBggrBgEFBQcB
AQRgMF4wNgYIKwYBBQUHMAKGKmh0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NvbW9k
b1VUTlNHQ0NBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2Eu
Y29tMA0GCSqGSIb3DQEBBQUAA4IBAQAtlzR6QDLqcJcvgTtLeRJ3rvuq1xqo2l/z
odueTZbLN3qo6u6bldudu+Ennv1F7Q5Slqz0J790qpL0pcRDAB8OtXj5isWMcL2a
ejGjKdBZa0wztSz4iw+SY1dWrCRnilsvKcKxudokxeRiDn55w/65g+onO7wdQ7Vu
F6r7yJiIatnyfKH2cboZT7g440LX8NqxwCPf3dfxp+0Jj1agq8MLy6SSgIGSH6lv
+Wwz3D5XxqfyH8wqfOQsTEZf6/Nh9yvENZ+NWPU6g0QO2JOsTGvMd/QDzczc4BxL
XSXaPV7Od4rhPsbXlM1wSTz/Dr0ISKvlUhQVnQ6cGodWaK2cCQBk
-----END CERTIFICATE-----`

var comodoRoot = `-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIQToEtioJl4AsC7j41AkblPTANBgkqhkiG9w0BAQUFADCB
gTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxJzAlBgNV
BAMTHkNPTU9ETyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjEyMDEwMDAw
MDBaFw0yOTEyMzEyMzU5NTlaMIGBMQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3Jl
YXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01P
RE8gQ0EgTGltaXRlZDEnMCUGA1UEAxMeQ09NT0RPIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0ECLi3LjkRv3
UcEbVASY06m/weaKXTuH+7uIzg3jLz8GlvCiKVCZrts7oVewdFFxze1CkU1B/qnI
2GqGd0S7WWaXUF601CxwRM/aN5VCaTwwxHGzUvAhTaHYujl8HJ6jJJ3ygxaYqhZ8
Q5sVW7euNJH+1GImGEaaP+vB+fGQV+useg2L23IwambV4EajcNxo2f8ESIl33rXp
+2dtQem8Ob0y2WIC8bGoPW43nOIv4tOiJovGuFVDiOEjPqXSJDlqR6sA1KGzqSX+
DT+nHbrTUcELpNqsOO9VUCQFZUaTNE8tja3G1CEZ0o7KBWFxB3NH5YoZEr0ETc5O
nKVIrLsm9wIDAQABo4GOMIGLMB0GA1UdDgQWBBQLWOWLxkwVN6RAqTCpIb5HNlpW
/zAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBJBgNVHR8EQjBAMD6g
PKA6hjhodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9DZXJ0aWZpY2F0aW9u
QXV0aG9yaXR5LmNybDANBgkqhkiG9w0BAQUFAAOCAQEAPpiem/Yb6dc5t3iuHXIY
SdOH5EOC6z/JqvWote9VfCFSZfnVDeFs9D6Mk3ORLgLETgdxb8CPOGEIqB6BCsAv
IC9Bi5HcSEW88cbeunZrM8gALTFGTO3nnc+IlP8zwFboJIYmuNg4ON8qa90SzMc/
RxdMosIGlgnW2/4/PEZB31jiVg88O8EckzXZOFKs7sjsLjBOlDW0JB9LeGna8gI4
zJVSk/BwJVmcIGfE7vmLV2H0knZ9P4SNVbfo5azV8fUZVqZa+5Acr5Pr5RzUZ5dd
BA6+C4OmF4O5MBKgxTMVBbkN+8cFduPYSo38NBejxiEovjBFMR7HeL5YYTisO+IB
ZQ==
-----END CERTIFICATE-----`

var nameConstraintsLeaf = `-----BEGIN CERTIFICATE-----
MIIHMTCCBRmgAwIBAgIIIZaV/3ezOJkwDQYJKoZIhvcNAQEFBQAwgcsxCzAJBgNV
BAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEj
MCEGA1UECxMaR2xvYmFsIFF1YWxpZmllZCBTZXJ2ZXIgQ0ExPDA6BgNVBAoTM1Zp
cmdpbmlhIFBvbHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUgVW5pdmVyc2l0
eTExMC8GA1UEAxMoVmlyZ2luaWEgVGVjaCBHbG9iYWwgUXVhbGlmaWVkIFNlcnZl
ciBDQTAeFw0xMzA5MTkxNDM2NTVaFw0xNTA5MTkxNDM2NTVaMIHNMQswCQYDVQQG
EwJVUzERMA8GA1UECAwIVmlyZ2luaWExEzARBgNVBAcMCkJsYWNrc2J1cmcxPDA6
BgNVBAoMM1ZpcmdpbmlhIFBvbHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUg
VW5pdmVyc2l0eTE7MDkGA1UECwwyVGVjaG5vbG9neS1lbmhhbmNlZCBMZWFybmlu
ZyBhbmQgT25saW5lIFN0cmF0ZWdpZXMxGzAZBgNVBAMMEnNlY3VyZS5pZGRsLnZ0
LmVkdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkOyPpsOK/6IuPG
WnIBlVwlHzeYf+cUlggqkLq0b0+vZbiTXgio9/VCuNQ8opSoss7J7o3ygV9to+9Y
YwJKVC5WDT/y5JWpQey0CWILymViJnpNSwnxBc8A+Q8w5NUGDd/UhtPx/U8/hqbd
WPDYj2hbOqyq8UlRhfS5pwtnv6BbCTaY11I6FhCLK7zttISyTuWCf9p9o/ggiipP
ii/5oh4dkl+r5SfuSp5GPNHlYO8lWqys5NAPoDD4fc/kuflcK7Exx7XJ+Oqu0W0/
psjEY/tES1ZgDWU/ParcxxFpFmKHbD5DXsfPOObzkVWXIY6tGMutSlE1Froy/Nn0
OZsAOrcCAwEAAaOCAhMwggIPMIG4BggrBgEFBQcBAQSBqzCBqDBYBggrBgEFBQcw
AoZMaHR0cDovL3d3dy5wa2kudnQuZWR1L2dsb2JhbHF1YWxpZmllZHNlcnZlci9j
YWNlcnQvZ2xvYmFscXVhbGlmaWVkc2VydmVyLmNydDBMBggrBgEFBQcwAYZAaHR0
cDovL3Z0Y2EtcC5lcHJvdi5zZXRpLnZ0LmVkdTo4MDgwL2VqYmNhL3B1YmxpY3dl
Yi9zdGF0dXMvb2NzcDAdBgNVHQ4EFgQUp7xbO6iHkvtZbPE4jmndmnAbSEcwDAYD
VR0TAQH/BAIwADAfBgNVHSMEGDAWgBS8YmAn1eM1SBfpS6tFatDIqHdxjDBqBgNV
HSAEYzBhMA4GDCsGAQQBtGgFAgICATAOBgwrBgEEAbRoBQICAQEwPwYMKwYBBAG0
aAUCAgMBMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cucGtpLnZ0LmVkdS9nbG9i
YWwvY3BzLzBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vd3d3LnBraS52dC5lZHUv
Z2xvYmFscXVhbGlmaWVkc2VydmVyL2NybC9jYWNybC5jcmwwDgYDVR0PAQH/BAQD
AgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHREEFjAUghJz
ZWN1cmUuaWRkbC52dC5lZHUwDQYJKoZIhvcNAQEFBQADggIBAEgoYo4aUtatY3gI
OyyKp7QlIOaLbTJZywESHqy+L5EGDdJW2DJV+mcE0LDGvqa2/1Lo+AR1ntsZwfOi
Y718JwgVVaX/RCd5+QKP25c5/x72xI8hb/L1bgS0ED9b0YAhd7Qm1K1ot82+6mqX
DW6WiGeDr8Z07MQ3143qQe2rBlq+QI69DYzm2GOqAIAnUIWv7tCyLUm31b4DwmrJ
TeudVreTKUbBNB1TWRFHEPkWhjjXKZnNGRO11wHXcyBu6YekIvVZ+vmx8ePee4jJ
3GFOi7lMuWOeq57jTVL7KOKaKLVXBb6gqo5aq+Wwt8RUD5MakrCAEeQZj7DKaFmZ
oQCO0Pxrsl3InCGvxnGzT+bFVO9nJ/BAMj7hknFdm9Jr6Bg5q33Z+gnf909AD9QF
ESqUSykaHu2LVdJx2MaCH1CyKnRgMw5tEwE15EXpUjCm24m8FMOYC+rNtf18pgrz
5D8Jhh+oxK9PjcBYqXNtnioIxiMCYcV0q5d4w4BYFEh71tk7/bYB0R55CsBUVPmp
timWNOdRd57Tfpk3USaVsumWZAf9MP3wPiC7gb4d5tYEEAG5BuDT8ruFw838wU8G
1VvAVutSiYBg7k3NYO7AUqZ+Ax4klQX3aM9lgonmJ78Qt94UPtbptrfZ4/lSqEf8
GBUwDrQNTb+gsXsDkjd5lcYxNx6l
-----END CERTIFICATE-----`

var nameConstraintsIntermediate1 = `-----BEGIN CERTIFICATE-----
MIINLjCCDBagAwIBAgIRIqpyf/YoGgvHc8HiDAxAI8owDQYJKoZIhvcNAQEFBQAw
XDELMAkGA1UEBhMCQkUxFTATBgNVBAsTDFRydXN0ZWQgUm9vdDEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEbMBkGA1UEAxMSVHJ1c3RlZCBSb290IENBIEcyMB4X
DTEyMTIxMzAwMDAwMFoXDTE3MTIxMzAwMDAwMFowgcsxCzAJBgNVBAYTAlVTMREw
DwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVyZzEjMCEGA1UECxMa
R2xvYmFsIFF1YWxpZmllZCBTZXJ2ZXIgQ0ExPDA6BgNVBAoTM1ZpcmdpbmlhIFBv
bHl0ZWNobmljIEluc3RpdHV0ZSBhbmQgU3RhdGUgVW5pdmVyc2l0eTExMC8GA1UE
AxMoVmlyZ2luaWEgVGVjaCBHbG9iYWwgUXVhbGlmaWVkIFNlcnZlciBDQTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALgIZhEaptBWADBqdJ45ueFGzMXa
GHnzNxoxR1fQIaaRQNdCg4cw3A4dWKMeEgYLtsp65ai3Xfw62Qaus0+KJ3RhgV+r
ihqK81NUzkls78fJlADVDI4fCTlothsrE1CTOMiy97jKHai5mVTiWxmcxpmjv7fm
5Nhc+uHgh2hIz6npryq495mD51ZrUTIaqAQN6Pw/VHfAmR524vgriTOjtp1t4lA9
pXGWjF/vkhAKFFheOQSQ00rngo2wHgCqMla64UTN0oz70AsCYNZ3jDLx0kOP0YmM
R3Ih91VA63kLqPXA0R6yxmmhhxLZ5bcyAy1SLjr1N302MIxLM/pSy6aquEnbELhz
qyp9yGgRyGJay96QH7c4RJY6gtcoPDbldDcHI9nXngdAL4DrZkJ9OkDkJLyqG66W
ZTF5q4EIs6yMdrywz0x7QP+OXPJrjYpbeFs6tGZCFnWPFfmHCRJF8/unofYrheq+
9J7Jx3U55S/k57NXbAM1RAJOuMTlfn9Etf9Dpoac9poI4Liav6rBoUQk3N3JWqnV
HNx/NdCyJ1/6UbKMJUZsStAVglsi6lVPo289HHOE4f7iwl3SyekizVOp01wUin3y
cnbZB/rXmZbwapSxTTSBf0EIOr9i4EGfnnhCAVA9U5uLrI5OEB69IY8PNX0071s3
Z2a2fio5c8m3JkdrAgMBAAGjggh5MIIIdTAOBgNVHQ8BAf8EBAMCAQYwTAYDVR0g
BEUwQzBBBgkrBgEEAaAyATwwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xv
YmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wEgYDVR0TAQH/BAgwBgEB/wIBADCCBtAG
A1UdHgSCBscwggbDoIIGvzASghAzZGJsYWNrc2J1cmcub3JnMBiCFmFjY2VsZXJh
dGV2aXJnaW5pYS5jb20wGIIWYWNjZWxlcmF0ZXZpcmdpbmlhLm9yZzALgglhY3Zj
cC5vcmcwCYIHYmV2Lm5ldDAJggdiZXYub3JnMAuCCWNsaWdzLm9yZzAMggpjbWl3
ZWIub3JnMBeCFWVhc3Rlcm5icm9va3Ryb3V0Lm5ldDAXghVlYXN0ZXJuYnJvb2t0
cm91dC5vcmcwEYIPZWNvcnJpZG9ycy5pbmZvMBOCEWVkZ2FycmVzZWFyY2gub3Jn
MBKCEGdldC1lZHVjYXRlZC5jb20wE4IRZ2V0LWVkdWNhdGVkLmluZm8wEYIPZ2V0
ZWR1Y2F0ZWQubmV0MBKCEGdldC1lZHVjYXRlZC5uZXQwEYIPZ2V0ZWR1Y2F0ZWQu
b3JnMBKCEGdldC1lZHVjYXRlZC5vcmcwD4INaG9raWVjbHViLmNvbTAQgg5ob2tp
ZXBob3RvLmNvbTAPgg1ob2tpZXNob3AuY29tMBGCD2hva2llc3BvcnRzLmNvbTAS
ghBob2tpZXRpY2tldHMuY29tMBKCEGhvdGVscm9hbm9rZS5jb20wE4IRaHVtYW53
aWxkbGlmZS5vcmcwF4IVaW5uYXR2aXJnaW5pYXRlY2guY29tMA+CDWlzY2hwMjAx
MS5vcmcwD4INbGFuZHJlaGFiLm9yZzAggh5uYXRpb25hbHRpcmVyZXNlYXJjaGNl
bnRlci5jb20wFYITbmV0d29ya3ZpcmdpbmlhLm5ldDAMggpwZHJjdnQuY29tMBiC
FnBldGVkeWVyaXZlcmNvdXJzZS5jb20wDYILcmFkaW9pcS5vcmcwFYITcml2ZXJj
b3Vyc2Vnb2xmLmNvbTALgglzZGltaS5vcmcwEIIOc292YW1vdGlvbi5jb20wHoIc
c3VzdGFpbmFibGUtYmlvbWF0ZXJpYWxzLmNvbTAeghxzdXN0YWluYWJsZS1iaW9t
YXRlcmlhbHMub3JnMBWCE3RoaXNpc3RoZWZ1dHVyZS5jb20wGIIWdGhpcy1pcy10
aGUtZnV0dXJlLmNvbTAVghN0aGlzaXN0aGVmdXR1cmUubmV0MBiCFnRoaXMtaXMt
dGhlLWZ1dHVyZS5uZXQwCoIIdmFkcy5vcmcwDIIKdmFsZWFmLm9yZzANggt2YXRl
Y2guaW5mbzANggt2YXRlY2gubW9iaTAcghp2YXRlY2hsaWZlbG9uZ2xlYXJuaW5n
LmNvbTAcghp2YXRlY2hsaWZlbG9uZ2xlYXJuaW5nLm5ldDAcghp2YXRlY2hsaWZl
bG9uZ2xlYXJuaW5nLm9yZzAKggh2Y29tLmVkdTASghB2aXJnaW5pYXZpZXcubmV0
MDSCMnZpcmdpbmlhcG9seXRlY2huaWNpbnN0aXR1dGVhbmRzdGF0ZXVuaXZlcnNp
dHkuY29tMDWCM3ZpcmdpbmlhcG9seXRlY2huaWNpbnN0aXR1dGVhbmRzdGF0ZXVu
aXZlcnNpdHkuaW5mbzA0gjJ2aXJnaW5pYXBvbHl0ZWNobmljaW5zdGl0dXRlYW5k
c3RhdGV1bml2ZXJzaXR5Lm5ldDA0gjJ2aXJnaW5pYXBvbHl0ZWNobmljaW5zdGl0
dXRlYW5kc3RhdGV1bml2ZXJzaXR5Lm9yZzAZghd2aXJnaW5pYXB1YmxpY3JhZGlv
Lm9yZzASghB2aXJnaW5pYXRlY2guZWR1MBOCEXZpcmdpbmlhdGVjaC5tb2JpMByC
GnZpcmdpbmlhdGVjaGZvdW5kYXRpb24ub3JnMAiCBnZ0LmVkdTALggl2dGFyYy5v
cmcwDIIKdnQtYXJjLm9yZzALggl2dGNyYy5jb20wCoIIdnRpcC5vcmcwDIIKdnRs
ZWFuLm9yZzAWghR2dGtub3dsZWRnZXdvcmtzLmNvbTAYghZ2dGxpZmVsb25nbGVh
cm5pbmcuY29tMBiCFnZ0bGlmZWxvbmdsZWFybmluZy5uZXQwGIIWdnRsaWZlbG9u
Z2xlYXJuaW5nLm9yZzATghF2dHNwb3J0c21lZGlhLmNvbTALggl2dHdlaS5jb20w
D4INd2l3YXR3ZXJjLmNvbTAKggh3dnRmLm9yZzAIgQZ2dC5lZHUwd6R1MHMxCzAJ
BgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTETMBEGA1UEBxMKQmxhY2tzYnVy
ZzE8MDoGA1UEChMzVmlyZ2luaWEgUG9seXRlY2huaWMgSW5zdGl0dXRlIGFuZCBT
dGF0ZSBVbml2ZXJzaXR5MCcGA1UdJQQgMB4GCCsGAQUFBwMCBggrBgEFBQcDAQYI
KwYBBQUHAwkwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5nbG9iYWxzaWdu
LmNvbS9ncy90cnVzdHJvb3RnMi5jcmwwgYQGCCsGAQUFBwEBBHgwdjAzBggrBgEF
BQcwAYYnaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3RydXN0cm9vdGcyMD8G
CCsGAQUFBzAChjNodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC90
cnVzdHJvb3RnMi5jcnQwHQYDVR0OBBYEFLxiYCfV4zVIF+lLq0Vq0Miod3GMMB8G
A1UdIwQYMBaAFBT25YsxtkWASkxt/MKHico2w5BiMA0GCSqGSIb3DQEBBQUAA4IB
AQAyJm/lOB2Er4tHXhc/+fSufSzgjohJgYfMkvG4LknkvnZ1BjliefR8tTXX49d2
SCDFWfGjqyJZwavavkl/4p3oXPG/nAMDMvxh4YAT+CfEK9HH+6ICV087kD4BLegi
+aFJMj8MMdReWCzn5sLnSR1rdse2mo2arX3Uod14SW+PGrbUmTuWNyvRbz3fVmxp
UdbGmj3laknO9YPsBGgHfv73pVVsTJkW4ZfY/7KdD/yaVv6ophpOB3coXfjl2+kd
Z4ypn2zK+cx9IL/LSewqd/7W9cD55PCUy4X9OTbEmAccwiz3LB66mQoUGfdHdkoB
jUY+v9vLQXmaVwI0AYL7g9LN
-----END CERTIFICATE-----`

var nameConstraintsIntermediate2 = `-----BEGIN CERTIFICATE-----
MIIEXTCCA0WgAwIBAgILBAAAAAABNuk6OrMwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMjA0MjUxMTAw
MDBaFw0yNzA0MjUxMTAwMDBaMFwxCzAJBgNVBAYTAkJFMRUwEwYDVQQLEwxUcnVz
dGVkIFJvb3QxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGzAZBgNVBAMTElRy
dXN0ZWQgUm9vdCBDQSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AKyuvqrtcMr7g7EuNbu4sKwxM127UsCmx1RxbxxgcArGS7rjiefpBH/w4LYrymjf
vcw1ueyMNoqLo9nJMz/ORXupb35NNfE667prQYHa+tTjl1IiKpB7QUwt3wXPuTMF
Ja1tXtjKzkqJyuJlNuPKT76HcjgNqgV1s9qG44MD5I2JvI12du8zI1bgdQ+l/KsX
kTfbGjUvhOLOlVNWVQDpL+YMIrGqgBYxy5TUNgrAcRtwpNdS2KkF5otSmMweVb5k
hoUVv3u8UxQH/WWbNhHq1RrIlg/0rBUfi/ziShYFSB7U+aLx5DxPphTFBiDquQGp
tB+FC4JvnukDStFihZCZ1R8CAwEAAaOCASMwggEfMA4GA1UdDwEB/wQEAwIBBjAP
BgNVHRMBAf8EBTADAQH/MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAdBgNVHQ4E
FgQUFPblizG2RYBKTG38woeJyjbDkGIwMwYDVR0fBCwwKjAooCagJIYiaHR0cDov
L2NybC5nbG9iYWxzaWduLm5ldC9yb290LmNybDA+BggrBgEFBQcBAQQyMDAwLgYI
KwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjEwHwYD
VR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswDQYJKoZIhvcNAQEFBQADggEB
AL7IG0l+k4LkcpI+a/kvZsSRwSM4uA6zGX34e78A2oytr8RG8bJwVb8+AHMUD+Xe
2kYdh/Uj/waQXfqR0OgxQXL9Ct4ZM+JlR1avsNKXWL5AwYXAXCOB3J5PW2XOck7H
Zw0vRbGQhjWjQx+B4KOUFg1b3ov/z6Xkr3yaCfRQhXh7KC0Bc0RXPPG5Nv5lCW+z
tbbg0zMm3kyfQITRusMSg6IBsDJqOnjaiaKQRcXiD0Sk43ZXb2bUKMxC7+Td3QL4
RyHcWJbQ7YylLTS/x+jxWIcOQ0oO5/54t5PTQ14neYhOz9x4gUk2AYAW6d1vePwb
hcC8roQwkHT7HvfYBoc74FM=
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_permitted_ok = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUCf6ZyZVyoojtih3/xWDxu9ThBcQwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDQ3WhcNNDAwNjEyMjM0
NDQ3WjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAOiv42C7m4dqfMrONXUkc1qJ4b35ecKB50QGHf/G33QGTvX3ZPgJcsbY
DEHZ3avrvPoIVntktNYFJ8OrDZ2HWNdECMuPELLZsFkWCRoXSg/924pO35M9GsbQ
8k0JLrQYQ00Wpl8X/CYeUJ/Y+M6Op9Y8U8zSp6qpTV/hfuSixeiVE6NsuIjLY+DW
H+7UlgapR5fO3UuLEowaCaY6YC9FCljYrQ9z8LfFXL8g8g1s/7kzJJMfqtrag/op
Km2IB9cRCBQoAnsxyq0DmSiq5nKmD1A+f0OI5v+xbCtzBiwpX8aBN0vEl3wt9WAU
JwzfZGjc9/7CCAt1cLLgSbMm8XIT4l0CAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAHvkDdR6ktMaz2/I8bOo
o0e0TPgEdt3u4SxUhK48Kunm3Rg93Z6/Off57hv/M4X3UkCsQeUhQ556EbNLrwpG
sUfMAdtfpZAIgPK75Mr/aDRvGf9grdt7s0jzO96rboFKpUFKpP3TFgaVDDuse92I
3KEh6N5aryTumz8W/qddbw/CcetXnucKQw4Hq3o+uPD8Neu8sWJjWeUXPYs2r5Lu
VCjkeTG/iMovWwHTHqSdLSs+SQP7RB35W573qDP02u1iwiS+hUXc7uO2/dujF4pS
NI4IEgWvKtPKPIUdFwPaNn4ycOvgFdYZTrWDMdq4cpgAD2Z945VA5K6KtUSW3xNn
2VA=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_permitted_ok = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NDdaFw00MDAzMDQyMzQ0NDdaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7oC2drjJaDbo7QnCy
8tbyVZm6QeKZ/V/i7RSbdnf0RHNDM85J2i2qBrT5n2uRoV3D0/Ln8z/VgO/AqFhI
B3PNcyrTn2Cjf9ZLQJFuo8MQlouQgwRgai8tRWNS0IUJFjQeG49+JEm5tPIHLEoC
Hu6WfOnWTQ5otS/crdxEiMZ40UBAL/INw2XnlttY+H+2eyHrmzP0OvPASVkekZgs
7CtMer11GIAAS9zfKq67fpXTUuAZoMFYjEYRr+/qfY0rMwnC63YhfpOx3ob2KLPl
IMntwc95rHuXPYA1Fwss0YfWM2pPsjRtegYWpslhS1XZLWRQlr0uGj1qyiT3Ltcv
W1elAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AJkTjOcfHRnS9sjVu4MjUrKAR5g6QLwr0ae46hEjLBNR0GYdl6E3hv0UwCKHBG7Z
XnF69GH5NOpIcaJqeInpCabOi2tMDoX9IjcvLBIYLtEzltrR/hjM7N6kNYRLhY6U
voqQIUx0pSMIiCyg5ic8nfD04NR27dwxgu2aqx23oZw22FM1rRfvcfGWlRCK/gRv
Y/VE0jmGSRb3luBd9AEca0M9jSZ1pYo80Sq7tx3Dh0oNuxYQuOeUhwSb54tuR7xE
tD6UJw2/yzpUDIkFtnlohEC2IdxiOq8RHJkzzjnpBMsKeTgERIh8Vtwt7eNZ+uJ4
Ac5kF0XcLUKZljv7MoFWPIs=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_permitted_ok = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ0N1oXDTM5MTEyNTIzNDQ0N1owPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsUWA857XFQVL7tASKR8y
iUVy8eXPjk/Zl5D3Vb/5BeIoQ5zqLimyjkxjLaKTWnEl64byTKyVvACwzaCQaBs9
2SobUDCFYhw6iPfND32jmuONSdtLvJYuxVDpp+wr9bArEx4+b9C7n+rrFszgrcns
wMOVNZeZXomekLqO+WL9CLt4HHmXQcmUStl2/VqN4XwKMHWivECyUL5Y4RRAxkfb
rjmJoNtqiiswNzhalHod5UUvJADul5xCbY7NPn4q1/SzLwX/2WaOVfSuYzQdNabc
NgXc8AFfxNfRMJvmLPOcPMocFRMItUMBqpxyWRFDLKxnIe+ymgsvAWQLe9ixGz0O
mwIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQBML4KdOb+vZt9Xemb+i2fOZjiAlZLPa3zz7HHt7b/zSB9MDiRo
XNLT/zf+xD76rMGo6wCDDs9lqUyveBun5siXYAObsG/pOB/AJ+w4GTCm/rCngbOG
PhRWhLumCdGt4NQ2uZweNbDnGKUtjlFbG1KUabrV2X2eM0SnZnh8hq1qFr7SE/pF
Ro8HCf1ctqe0RG7mmqGWx5ilH9oMSG6Pc60iEkRB7hnBkTft7r2XIDCR4mVGJamj
JYn+C43+lBSFyAIkCHRbAOoxZo0WZC49Mahm8aNwsKtXlCCP6u/ESpGEGvMMsnIJ
MLp5X4M72jmFYuRgCMNfCGiVEJqvJmeismjX
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_permitted_dirname_multirdn = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUOjzggjKgLVBb637t75xq0PhCUXUwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDQ4WhcNNDAwNjEyMjM0
NDQ4WjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALqeJ5JPi92OJZw3omUnJw6IGrAK8KwfrCeDVsxII5Jg1AATmeEVd/KY
2vSTdU8eEx1odC7icatEKfN5TnSR4MFGPfQ74zIenD9IuZi8OjdiRGMS65ZvSZhR
gD88aKELIvwZzwBCgNd9i8RvzRodHhnmmDJ8MQW5yTnwu261jqODCDuXJidllVPB
pZy9O2rQ8bQ1hyl/1ZZxTHgKTsFj4fdpjW8oq2QgEBIiaVpdhl8iMnAMmiAlF9s4
x/i5cGdqui4wpUYBQfCvTY2a+hG0PQaBDX3fGNe0kTHTJQwI1GsvMc1Rpnyzs+6P
BlD5oBffhngAIvyTrfDhAAfF0bouQD0CAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAJiBUa1P4ccHeAtdYkqw
ZeogyfSydfR9P0aSsuhVfZBU65gcsaNfhxGtQ2WW+BXFNK8YH3vp2rif+A0j9RG1
KhvEUEOjDAQEkRa4uuUnYMC/vjeV7QDeEsHOZF01Bp5HkkBDgu5GANkW0ea/h4m6
GnGQ9UW/RudJVAu00Swr1TBAk6wyAQmRxUwqpEA26EXzt2yfKTHlrDIzqjoB5hWG
Jh7FqhYSWF4dlnj4uBGrtklbfKrUAVzYcRe1rW1lMivOFHGMO07WYDfSrGE17KTt
QsDsLN28WZhx1u9YoluR5iLGF+fyBMsZCoIu/E7i0WIIR0O9T6rFpsZjzMyokTZ+
1y8=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_permitted_dirname_multirdn = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NDhaFw00MDAzMDQyMzQ0NDhaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK4DcFqHSbi+eMsEPC
OZgA0WiwStLMFw3MwZ9mp1gJDo6BAVav3osAomOoxB1A8ffAX0UOQZfeGdlXP2GN
S+0EYFOSNxzL5nwszygDbSnHOkwlSBlFNLvDi8qQ9YesSFTGt0LBeoz0k/VYP3y0
sMGolcZB2quVn/F2GXGMmNsZCKyEbEmHoAp6a15lXvBLVEVVSbpBKEdi4jy6840q
8Y75sBCD3N4q3uUukCdAFdlgD5zidn3d3+YJu/j/OJ7d5/Pk/R5O+qVVzwFn4SAO
hZZDTa6eG4dIDkkcdbaE9Ys6ep1oP/lRgBe9QD3TzkrQb/RIDXRJziBp2akd+LFf
xYwrAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
ALFbPzdbzNuCI/qs34rV5K1nR7X/Lq85Gt0DbSKbcJV1DC/d9HTFl9Mi1G2AU1To
YIuG52QZm7534heGvllsn4W1yDEwZCfcEwFJqNZGp6PNM+8+G5+7JKyvuKLeWtWF
I5/oBeX/qzudIHvx97p/LRQ56E2fp11lExmMRIkYWVUPQTdylnOXZQ61A7Xyn3xv
bgXaf/nBC/zBnQ1atsVYtHpyt8JnidYxnsldVXoOqe3sVFq19zIrLamEJErA4xYS
b/dTNMuHrCUNHnqsRaiPgvMFLF+wr+O7R95tJRLFZReb9xUU/BaYjabLN3ViOw9N
7SKwkY3laFzYiSc0Dr4EhWE=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_permitted_dirname_multirdn = `-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ0OFoXDTM5MTEyNTIzNDQ0OFowWDETMBEGCgmSJomT8ixk
ARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4YW1wbGUxGTAXBgoJkiaJk/IsZAEZ
FglwZXJtaXR0ZWQxDTALBgNVBAMMBExlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC+d487XDxy19YHRhebr6vwACM/quLTIht/WdoKcrXUAwWOlrXP
6cK6ekr8JWJsBXeI4GpFHv+ZLmxadYCWdZmSf5r2glUNETGoRLrFwyW1riGJigDK
L0Yuv25avRD+7VkDfs/pkHStaWRQ0CNbLEsypNujSen8GMqw3JSIdehNTDlErDpl
OY1MNTpYOOe65GC481FuxdpwVfoUShSEXC5FCF0bImBdKgbkU5cBeRUOgzIp/ANe
t/cCOeP6x9GqH0xbt9pnNfv1hHndIGITuzmzZZ8KX+gzRVly6bQ4K2HDlzgL8cNv
0pw0MIMUH9x5UtRhyvDtY2qir6fjukYQVlEpAgMBAAGjHzAdMBsGA1UdEQQUMBKC
EGxlYWYuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQENBQADggEBAIBpybozqH+AtD0a
v89pZrnOIKSekdRBqgL2uwMuak99aNa4tqx1X4qMej9cbiQjYBBCCNitIuAmQTyd
a0MCvcoiCCVaiygqduLyLJV9FKPhOIh7/dUAKamPSdnGxNdg2Pb/B8EyZaIyz/RK
4i1i0fNFQdstYrcT/sGr8UR7k7q7xsYiT5aIGUAQZFunq9HrjuzUVarm24xDXMG7
9fcW79lhxK9OhFQZHLdaSzcwvkNc4j2aB/b8Yhoth955wROXF/2QGLfDjgvtgOsA
OiJOtt3RIoQtV08UClUfOdUTQjOJr9140qtvd1WkeKeftYeHtHpDfQx+oyFTexn8
RKfy9P8=
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_notpermitted_rootca = `-----BEGIN CERTIFICATE-----
MIIDsjCCApqgAwIBAgIUcczaknDNG0WPrt+RCoq8UxE1KU0wDQYJKoZIhvcNAQEL
BQAwOjELMAkGA1UEBhMCRk8xDDAKBgNVBAgMA0FueTEMMAoGA1UECgwDT3JnMQ8w
DQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDQ4WhcNNDAwNjEyMjM0NDQ4WjA6
MQswCQYDVQQGEwJGTzEMMAoGA1UECAwDQW55MQwwCgYDVQQKDANPcmcxDzANBgNV
BAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIVw3Am
qybiYS6ejJG9+Cte6DvlSXJeq4mYQk0LH3sg7kMCQXSPjMyZ7v6sshrd+GjYKnGm
87NpzFUp0EK1nJmuslVW5ETtRxHL3GpCQo0qtoEXpumJCmSI8agnqluFY4YqxVyp
K8vx2BA72YcQNCe7wQGHMgqKolGjKjUTAEHFVzixaJgjvHSSdh9yHpUOBFoWvWt/
10nZabzr0IQX9o2DGhBuqo2WPji7HOZYfU21g8EXRNybCf6KPnKH7uCiqPOFu+oJ
xA26L8VygGIvniWUsZdFH8ymuxRnsPXymZMoeHy4bIflU8HlmbCS4WbjmEYBxWj0
5v2T0oFqEVxCIEECAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGKMIGHoIGEMDOkMTAv
MQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcw
TaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFt
cGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1UdEwEB/wQIMAYBAf8C
AQEwDQYJKoZIhvcNAQELBQADggEBAB970E+C4RQKUd2G388Hqs2WelqQHUNpVvFC
DAD3T9+pfnndW9pALYF8naS41+lYHN3HN73JCZo2N54MUakNRGNZtSIhGuWMdM3p
Ndz5CYw0z1rXEcWcvhqChF21eXn2MbJeC6hT2W8TS8KK2pnG89DGwQmfDBRp3nn3
Rj2RGX6O81e11v81oEGWHhJF5d5LUsDQEr7V55oB9JMjJ8+XsQpWe029q1p17HMR
86JqgEqGqxhp9h1mhtL2/8skvTV+s+hyHOxvYFQGS3dr6MVLYZjZj1TcA6k2xCW8
yYFxpQAy/orCUWbGXSUew2y7c+3tUpkvnbLupZeiiqyKqw53RvQ=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_notpermitted_rootca = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA6MQswCQYDVQQGEwJGTzEM
MAoGA1UECAwDQW55MQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RDQTAeFw0y
MDA2MTcyMzQ0NDhaFw00MDAzMDQyMzQ0NDhaMD8xCzAJBgNVBAYTAkZPMRIwEAYD
VQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3ViQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0Q8r0nlb5uB4FdUCy8ywl27dM
6vhK9hyjibiD4MPrmd8z7HVadVEqRNrmVYCEwh/2yLE7fXS66I0vd9qJNkZlaBYt
o/kkVJ4FCgNWAq5D/tR8/N03mYqYmdo38sCfFbbfH4TH6NWSClYl2lm1MjgdwLmy
z5CmRBIbTPR4VsK/G5Hl6uh8kboQPqR9L3JsEqRPlxB0AOpjVPDS7AjLpE8rfEDf
bfMVe1j1CdSmYan3/oYvSsg2HX6JZ4//Ka2dhw5shrkLhTvKsi7ZKMWyZKn5he+F
yFx2s/DhdrEGo1mC4cMiS0iIGIkFsP/0DrT7V6QKnn1bpuPoQ/59jQrPKDADAgMB
AAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBAEvP+l3T
aoy9i+1OpXTFD2OJSZp4qbuLZsyz8OWJfh7OR72SmQmuujCRmaZiAUhnCm+Hye2J
enTsgOg+ivJ1s2LmLheo/lP49uRIXQXD7EAnTlC7DUxlHmaqaD4zoIXv50bjpK95
nUHnChXtG8ohjbLNU9Vpoau1knDjRt6I8HISvhyZK4xl+RUZ3yGdA/fHEJoy/01e
+eXfnO/6DS43okpQVYK5fSc7pLesPGvekGLHaLdyAwPvAzC+bhzjL5g1gaSdYbD8
AzLdi8PHLbxHJIBZPxYMhwUjdz6lRH0SCsTWFrWJERwPphNHxI//Y3Gxm5M+8kVS
D0H3uSJwOfS8JD0=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_notpermitted_rootca = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ0OFoXDTM5MTEyNTIzNDQ0OFowPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzjY4bMjA/7wPMoHMQv6Z
tUKa9t/WXAm1LJMHSQshcsJqWYKjxNE+zUVVX2tJKxL1fp0KYjhbGmFafAcsZi/w
Mjj43W6jO1weLk66c1cXfnqflIemb/y73pJNnOOp+l3qdP98SsxnFthCdouSMNS1
H2jdOCf0vPEdVw5M8rOypzo+dzUQtJycF60Iq08/mRZSE4OOUsp05CavIDWSe1jL
r8d2ELWt5oI6P4yYOyec9zZ+QdgtaZI24besam9OemHjmlY1n4OQD5gXbur819Zb
CCdQ3GtY7iQbq0ehAyJwFbov++Om2RbnDe5+ZLnrYcSAs+Ev5X+94pzWNXk9VtvE
2QIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQB1XZX7ZXRJM4YUUXUZE5yx3ej3tV8/4SF7oXFZuhZ1QKz+To3t
yCPkqA0eNwUcxl+LQ4uWjVm/gT8HxXKL5arK7bjlD+sACh1d/Kpbz0JkfSNa55Da
gn42Z5HZLnIzSxA3FyQDjwZxoMquH6Hl21JO8RlHKSDzacEwzv5SPD8eKhv2IhyD
O/dTsn9gVLZ9bCoBVEXFlg9L5H+rmw3TY29ZofrP8VOrm3xT2dl1wQCjIJNkQDsy
DSGd1959IulS0/VHFR3AD3zLurzDqjqREYZ5oGwZYFEpUtA/PCuIykLR9kYEK6t8
nkCrY2/fNGhFGB3Vk9UD01u3u/fRQfCsFyf5
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_notpermitted_subca_missing = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUOZnUJpd1fjyoR4/IO5WCiAi+PvowDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDQ4WhcNNDAwNjEyMjM0
NDQ4WjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMDFX/Pn3LdxQxA7BNsnRFyO3o5WEyxyaDEIhbGoFm5aRnBe3jXaJNNg
KT9SoNHUXVqfm0y0d3jzZVmM5IjP56ZyL5N9Jo7Qev6TB4WbxO4od7AmIgG8e+wv
awLV223Yop0P/rhPG8cU4UYm4gWGHCi9gkyCGzKrNkz6csA5TTWOZ90VNn6MQzt4
IdENCVrREfr7kMyzF1tZV3CO+xdMyV/5JKrkIVUEGQzIyYsdp0PYE3RsdRiBGY0n
dWvqiyjhEc/IiChv0PP+rZltlHhXgFlyTdV0mVKIMPVk3376kpwLYcMU/Vk2MZ2Y
PQzThsvIZGtmRg6i6tr8l5WzfbgK2EsCAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAFFyzGvkIC4DBbQMCPbc
H46MlrLUxkN6B5cautRtDEHQ8ArCHQtGvUNNGKVRkr6dgdpJ1JJ+YPISFFGg0Hkm
Q1ampZLBW2SmzQM3eU0fdUIzNtCdLz5Uxqhz7/gpHOUXyEqpKJ3KezsbGp2USGXN
Anw1ZK0dwtDDYo/CLBQB/aRpT4CewoAVI+g2fti8HgZjaw+Bu9hB7FW1+BAliMSB
nS1qHGyMwTwWAh9F4eJNvDoBsvklrIgQYmAKtbAqbYxnIscp3vSHIMyj4k1+AJR3
XeJ5XxDbEO0ukwpWyRfwZnXvYRlETgeK5V2Qm974U3wO8sZtjOiYjR4Sc7uo7de7
QHI=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_notpermitted_subca_missing = `-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NDlaFw00MDAzMDQyMzQ0NDlaMDExCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDjAMBgNVBAMMBVN1YkNBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzv5q7cB8jpa1WAziOzX8MCWZ4L95gwpdB8Vq
7Rg/JXoALy0BWRPf+vwqXhsytXfTevLhsHNNkIu7ZWC5EZNkWJfShAlUXyy0aa/T
Qn3ALQ7uqwZvKTxmXXle6dLI55npcvV3+26TmzYwdSVaxO9oAY0RVl5xbQWHvLf0
dhSWvYllyiDEkJ4brrE9Los7eTPM6SaMU8OLqLJH3bxicfgWzZ9I6mfKSRgF6MCs
BwS5u3BRbJ7L33m+OxkGKnKoFJh4LsSoxEBfYdGkavkhSuluTnavbN9FJGqt+4W1
9c10wHABSAKXsPfIARVin3IRWIukyTFJt5nXJP8KMPliiQL7KQIDAQABoxMwETAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAQAIK4/rwCYokHaEG2fM
oYUfIMS/jFnpU7AT0Q+9Fgm4EazAdvC39car42jjHJbw1YF2AqQXFFG3kpRG1Lvl
q0po31/WHtOMGRcDilt8Qr3etMa2j7wKeUY38WvoeV2xa8KuVmNCSTYrFXr8MFmY
cfA3GSydibasgpd6jEn4jooj6J0kABLHk5j2F14CcRvuMQ4QFoi7vDOAK5sm0Ff+
zd1o00Rs3IGvlWUnNIa2vmij6y/8iHbCWCKw0vC01ZqD8RDD6520mUqPx/LLhaIn
H0koBpvbZ1SuPoN7pKpiKl40SY92vb2ESLozm4Ew/tmFiIcOgwia8MU9HXq8pXiD
MO+Y
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_notpermitted_subca_missing = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIBATANBgkqhkiG9w0BAQ0FADAxMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQ4wDAYDVQQDDAVTdWJDQTAeFw0yMDA2MTcyMzQ0
NDlaFw0zOTExMjUyMzQ0NDlaMD4xCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJt
aXR0ZWQxDDAKBgNVBAoMA09yZzENMAsGA1UEAwwETGVhZjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANcDUQdUZPpfHo2MJNmI/wQ//tuAlcEjqrAIJJa4
b0KcYmE68QxaN7imErm/03WPSY3wUmjtA0BJXMhidtDKy2TETXAvRSKjXovrXcft
rmt0sFl6fud1saSraZHp4x7OmFPYwjV5fTIM+a3eF+ncrp/mhsXonAEXq8AB0Tx+
tqZUYxQcXeeRgQWt9HF/ZZQ7UTjXqmDaumhPaaeWANlvjm30uy8HCVrMOAn93fgN
dTEHGjVPuIB/UyMz9KfTpr7WN3fyHIxlmuFEUwZo2InRK3XVMAZODJ3RDmIx/2jM
4BFs7rcYCV+wQsvCPQrxOqK5rS2gkZuAdeK/5fCiAEBM9UUCAwEAAaMfMB0wGwYD
VR0RBBQwEoIQbGVhZi5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQ0FAAOCAQEAStJA
zg4RBCHex5AX10P+fqAF1P1cSgtOOrpviFR4FXTrM46wuJZiSlbt3E/p+zEivnoW
SeVulXG0he3umVn2rO/9cBhczGCbQCkxZygVujKzkW8zqy4GN2lZQOZc3NWNGK03
IMuwij/zE8JSK3xMELfW5BEKPut87lSWOD4ezCnrsFlGGOmlKG8NhLHB3P+l9vmi
FND4NmH2766rTB2Q1fGaDK6vWfB4S/QmotR1NMdRusfgu/kjSr0ImJWbXHqtfTxg
0rFJdsil+AFy0AiW/4/f4EdDESd4pbKdwGONGNEeZiHVbKCICDewlQAR5sH0aHou
PCo5OTfZrymZRtEKzA==
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_notpermitted_subca_changed = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUe3SmR56/ASYLO6+vXN9pwIwj7w0wDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDQ5WhcNNDAwNjEyMjM0
NDQ5WjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAK9U8xt1FHV1W8Q2cD4ewmmoAtHTmNeH76sqN5X/5OaE9iM0NXePTzNx
OuIo0tFQ0L5e3PTPMEf9ayIA1i+gULKjhbYAw8NI55/olGGPRMpeJpE5PSJFg/DQ
eX4QwAIPTmH6xiSPVsc89VqCDbtunCtbWwQRtJ1Nws1tLJCpeCtcFVEiBg0bAze6
9QFqrmoc7Vb94JWHgxQEHFafdZI+EJQZ9KFIn0aypgX1aVp7h248OvmxAt0jm7al
2Pg7wHLQhdXxZWfETrV3IFhFPoy6dBin90ZB98Aw+gss1JWJYvdkodmkZMoIxCoE
6axLDhyogOMYiYp9NOO6uvA67JcV3aUCAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAJAYXOz00pd5rX3eJGdm
/OQclUUoAibHJZ2KUEBpqOJ1Noha3t7ei9TIl1ZR88KkYJtoVFi/2sOvhHE1+TJ/
lpSjcqCcLEMELtGvcNyOq4dVS5Eo3IOLrFxUYTBxIAFZZrZj7gWtAXZeQur5i94r
SoJmUqB4Ry0wNvImEEkhr9nA+wsYxDG1zgWtmPxKZs0rHkZWOZpXpZYaXQ5U9aQp
/g3Q1eJJ9OFn/vavd7ek26/Embo3TB//FdPJKCNsBCGUCSDUj/ZsgCpHZKOlOsB+
z3wvPaMeSBlWViG0IXEout+ePmHUDdJFyA3wzR2cb11Oi7IlzL07H2uqosmcZ0nj
DIk=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_notpermitted_subca_changed = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NDlaFw00MDAzMDQyMzQ0NDlaMDkxCzAJBgNVBAYTAkZP
MQwwCgYDVQQIDANBbnkxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3ViQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUxe+fE/HMM6A/cxvPl6/cckCv
ky/DLaY8rGkoo/cwZDwEq3hBvcNmhr0cVWyGcGNvK3aiXxDoopFm9Xn/A2ntE6ks
A3crk7q2TgzD0BGsojQ0qXtjg2a+aDH+Cjj8Tay2U1r9E8+Ey7xharaDgI9XpnIw
VPHn2aD2l7zAALEl87hqt3DNskeVktPYHPRS+/HcitblC7sLRILJV4JlJ1UIZ3Xl
4u8+loyCqYXe4VgYBKixxB5Pp5loqiNO52IL4vL2RcZ97KTliaIVF6VolcRqSkmF
CZMJci0UPV/i52Ft2RLCPz4EKNOAUHbuCyNj4aJ4Z1hlmO1o7FaqoQG8yY7RAgMB
AAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBAFOQV5H+
YKpPSwNMe58CihZ4tjfO7NeIC/gt3LPBdrPkRiELuMuBODSAOxEYK+jrKm/Ohtrz
DqGBx0rFDwmrc7wvDKji3ATvUj76Tx3c3yak5ePEXvnYUUKBZfsnTrcgQbVMb640
K4ESolprjjVeHDEgVa8nKWk/mk8JGxGGYD06jUaoGSf2M2nGzdR69SVf7FG+fAJd
QR5YpIN5Mp1Vy1L7hevOVUMwR84ldG171Xsaj+toVL4YraTXhzJTfdXg5ABIdOKr
kAFCjNJfU4VuaRJqN+4gWOmSEuGbLJTmMkT1UR6I9addCYiSQsIHqfycgiZHkASf
sIgrpXtSzaoe4pc=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_notpermitted_subca_changed = `-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJGTzEM
MAoGA1UECAwDQW55MQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNBMB4XDTIw
MDYxNzIzNDQ0OVoXDTM5MTEyNTIzNDQ0OVowPjELMAkGA1UEBhMCRk8xEjAQBgNV
BAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFmMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Zm8kWAEpVojRFlPuJzFqX789YLv
5xLbS1D8/jz4WOKRixFQk4AuE8sv6VxTlMSv8G9XX9iGLcoPF0CnTBKaCsOGXSV9
qxcW+6Qiof29mapgo0KKgaNN7qHLK5TGhpjcxrZnbSYELl/irUMInNYpeInss6cB
h64eEOiunCF3hTDt+ySAfajky2tFRNu6AZw9f71MFIud5lSNGraqSeve1Uh+KE84
QY1EbOTTeZmCXkweBFYYSaCUFfM1Ro0K5wVrKSndInDtGNbvPhtchKxhQC7So30J
5IORjjOxpfzNXDz/F/ITL9h+Ge7zK006wT1W4R1jZVl+2QdNBUTqBoRpOQIDAQAB
ox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBDQUA
A4IBAQDNuKbGKcn5n++1DAzkelygR/jGf9s0JksNNUxIBFkPlpcOM9nCJhuEVftm
vL+xtLbIAfFc6NsTxZPuYReMoqmYbZljxKRvNKCYSIp1SpZ0expFpE7lGcEiNH/b
52nzryhE9MGvEiCVSM3k6Xn2ClDgInaIqpYa3+NBAcoITjy4AfX52XLmEJD2SE88
x0yGuGWN+kH0hp+lLbMHD9nkNZ9vnup4GlQDPjocCRCyW1Yqr/x4808hYuWh4vR5
gNthif+VowJxbv6o8+eeQFM/MoYcJS29Fv17MMQ44tv07vW4FD5GCPOwPdQPJ6qC
Hr2KWB6mW0pVQZq9hjxa1PZjq/AR
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_notpermitted_leaf_missing = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUBCnFa8P+O6piDTKh6BPes9iE7vAwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDQ5WhcNNDAwNjEyMjM0
NDQ5WjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALWTGlyJkZ/3qR1O+FviuVNzRO/II0qwTqIbS58MK6/UqHKR9lBT2Zlz
aAj4yGeEtZppGbvO8Pw+yWZMMk/mPa97tbdzkUC/elBbUg7UyBcPoMDT6pHngl7l
ar3ubde+K/RFWu1aqcZlKr/jmaKvUhEAgsqMT73MV8XRbDaUr9DhldHQe7gi2Hu2
rW5FoYwdiwZmmF+jmWNmcc/ZoZa0A+Pdusr+XeC+k3P5Jrn37iCQRJ/Q4BJxrv0y
V8Q7X/eExPdhdFJPZTh9gemK2ZNeUmqxrxrVIy/Vt58SECVpS67MPb6u4I5Wr+We
J1H3ND7cgz4dHi+WWRE2QUubZwirwU8CAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAGs2ToR8fiUXW6Ud7aNP
z9fEO8eNSgV9yCZpT0/NGuHp+hcjaXY56xo3NIwVEq/LerGnDLWBokXkfFAInjSi
5GrIBmZR7rVqxfqOg50odUgD52vpVyjqsVEIdP8qjp6XtgPMp0QAaaOIjj/L6V7k
Rpp9v312sUvch5wCWSfyW5k5WRQV/SmUCthIuyGhw6REc+ZOxxm8m9Ahw6J3OViY
1GWZUrG1Qh6iWqrGQZOtFd5iqXrRqCSIyY7UBT2/cE7jrzoTjKTxNcimUawC3Ix0
iRuOlCYUBqao80167vIJcWqu1oms+A9u6D49Ja6XrYxysf7NaK5axOFqRmFHAYEQ
otc=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_notpermitted_leaf_missing = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NDlaFw00MDAzMDQyMzQ0NDlaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCo6wfyS4TIHXcBkclL
yv/YHbVacWYWj7apY+G25l4DGyro0YTAF7goQfSLFHKFnWK+q52dIbsIZ7MnAi2C
Jfd25bGttHsz8dhT7DcMJlIDLoWOcd4e4KYzVF+CiVpsznVzH44jBwHjBm2qV2KR
u/u2qir161zKunsCZd/AgGpHxNcJ5EHhQwW/jynr4qA9+fweuw6qa1S/b/mxxd8G
8c1SzGK3pM06M+CR/pOjnzObFtsv77TPGTu89/901gdBLax7rId4wCIYLwIr0/DB
TIrJvqBTBkrqxIn3rfDfQ3WKUa2iZFw/laCCMC6bF7yR2Aq9lwoDf07xYzHDeJ1S
Wke9AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AB8rIgpfLED9OAyK0hYjPe4BC7wvXFB/KFV0lMaKgwJOsKFahOYroyw1m93nXGux
vd8LMhBsAbLoDJAR8FAW8yhgrOCdI0Klv9F7F96OJAZ67J0wn85HS4jwGolZRgvT
VDfglwp1sqH7U+h4EuK4mEFrCB/cXb4AUJpB62zBcR8lDZQpQBZeURhAmwBR5nRO
gajZxBMhXvjjEmc1k3aPqTCFq7sAmhLpS4DWSOIoAwkeo85EHi3dPZ0kJopVxESE
nVQJtIM1vfa0up0dsK8c286orsaN+r7XFqngCY1q52xL27LiexZp0wiGqW9oi1Zd
oOncdhkvpHousxdP9DT340w=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_notpermitted_leaf_missing = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1MFoXDTM5MTEyNTIzNDQ1MFowMDELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDENMAsGA1UEAwwETGVhZjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKt5B4e2kjEKi70Fxqkv+g2KBvIiVE9Fg1D4sdpv
F/OOEIQ/yCNAl5GCinl24TGu/9pjMJSXmHRKYNXtPhjTCAWOhh7MRPXOcVQ9Sa1N
4uTQFQooz3gHtIWVeUzRAvl5SRDy9IN0claHdS7VOWUPrkV658/eV7BbMjPlQxrx
m/meUtj26B0BFQYOCGpRk/YAyS3aKlMICz0RrZqDmJH2zll60gm5t9hnzgI9+AXG
sTcSAFZLWadYnSEeLWT/HFgI+F9/RSQRb3NL2eGIf96EF//ab6Bwkkf7IxT0n2am
yxj+oRseQCkGU9Hn8KDVM4eDcZHKANAbLyZj08vj88N73UkCAwEAAaMfMB0wGwYD
VR0RBBQwEoIQbGVhZi5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQ0FAAOCAQEAmMm8
LSdEa+8HR0/tOuevc/bp8PfepiME20MBzkp9/CJeqBiryu4vSzuzd6i6rLGw3VrE
JWox9Ju4VcaptcXwv05CINrvrzFbi93UMmUGGTz634AeLOAQSk8nWwmo84qjbvAh
sXB2Bi2aZVSooh9h2+d6Zm916uWfkZR2iHwNHXzpWPfq4BZM48YQh6mY1SCNHiL7
IMaeHUrp6CLli7xjHYRSjYldiYDIeycN3SkbfVvMp4bWCBZ4qdR4RtcXIul6I4wQ
N7TANKK0oa2RMS4nEKPQeRogDf5Vt9L9R+OpUV8deyb1KPywFRJ78nlzGfdsiL13
jVrfHBkSphYjljc/1Q==
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_notpermitted_leaf_changed = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUeir4p8XxdPWLdvbhVDafSTVBzD4wDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUwWhcNNDAwNjEyMjM0
NDUwWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKh2BrO04S0u3JUh+yCsYkgU8M+6sCx8L7UYUVjyzcWqcAi6hWm1NaJv
zbvZdHopY1BoPbktqaP03Il1CySV4TV8V8RudKBnNYeOLXlc8OUlHd5FH+me0Y9I
wH5Jv2adh1MO5IVssUVDIqDkX4p7Gs2UzAU32G9V+iH6+1QFqOj/F/uICbSQNY6y
SE/tOf9inW5x2nxdOEJ5YmiSqQ+nUGRgq0+5kSWooXFzHhfVSYmiuuO7aPZOnmW2
Rk0iskheHnLwL3F8LGSx96ToRFl6hk/EJI2CE0UR31PdTGYmqBKV3C76TSibawMh
/DNxQ+BPwm91xDVo5fW88/zUsUGODQUCAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAEdtnkb9IftTDxSqxulq
EmnRS8MVya1zt+HNwNiMU8jvoS07M7ccoIi3GR+8VToWTRYtlhsLY31iiM65ZD+t
zTa2SAO74BAub1pgRH9s9mITlAJGSTCBPZunW2/bCul3vau+MKZLB1r0mSLAObS6
5Ydj1bSQWCs//OCunNAvQH7SoSLsttTYKRdzaOMhjzLGLJTyIHDB2HwWHZzCifDt
naZTFds9VaoDxXBsnFNZiSY2I042DZp4ftQom3JAlu2IdnpMVWLGqCZouzpCI4EP
qw3Su6ekSUz6KbZJbzlsrO6xCWmQ3RIiL1Lul2sCMznnyMh3UATKfKS2xRh+sLMn
DQs=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_notpermitted_leaf_changed = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTBaFw00MDAzMDQyMzQ0NTBaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmQdQG2xqxMOOmtdF7
hZrmFADZRi0dmEGf+ggNVkTRnEwMbvYn/Yux7DcFYamUP/ULddff/ij1P/N6iJEm
o9mR4IntBmSUpSKhTYCQFxlMR5HcEkTTVOC+BaNi/tOxkVC4aWvrEIM0Hp+EiYt/
a6ZnwpLGI9Jwel6IAf+vMFQaPdoDYJrAv1OUhxeysfPWT6UuZiNLW0/uYnyKBfWE
d8cHjUqJs+6gQkGK/HVan7L9MgpzGj7uhRunVFjS8H7QBUIDH9a24zHZYt4ST0r0
rcJ7iDHTL2EXavjBEXKNDCSW2WRS6hPVJdFU/3P7EGp5xUZF2QsBztOq5wgPvSNL
e7wZAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AIxpJeku+FuklM4wh7hpyMLJCgeoOHKtVSSV3vRGG0Y9PI/p+gnnz/IBA0pnCYiq
XHtqVp9hk6/DoKbWRq7/lXiYUdsHClhaXMKjZoXMdLPuhYSh4mbEgL6zkdtgvEVs
RQhgmYWhb5ddkiXTOfEdhscjSC+pSizzTqUq7S/donMI04drVe3ePRW1WLEqsXDq
GK5vLiXNAMcZfO7LF0cwRtAv8ZHwJSW137MFJumZV3MqSYF/6kBrvi69Yc60xwdN
x0qqkHPFKVful9kdk0tAsQb+q0pBWSSQ6g0IkwSnfvONWyNWwuY6QULryJDPrljq
Y7Xbi8UDMMLE91YWZsh2Bj0=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_notpermitted_leaf_changed = `-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1MFoXDTM5MTEyNTIzNDQ1MFowODELMAkGA1UEBhMCRk8x
DDAKBgNVBAgMA0FueTEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFmMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnax+6OUje5TLEe56CnceXS2Y4tav
EJbvTSpunOMYQlytHXvSR6P/fDc5sWL3AYeI1218aFJRHaHbCSg/Bu60RRmpZTuC
oHfat3dxygRwI4kAuDEege0ACWYQ/iFNqSug5QYdghAhuevO1nT5AcwhTVA88665
tjZhzTslIszlsgmol3Tc1bUH/SwXCWsUghjzLv0G914JwFQNQddrf1+/wOfVB6l8
O+9SpO/Y6hxQ/QOlAFn5/alZe9QSX4YQHIOZuedSEkLvLDiLOx05oi5FHmzVlIsd
nzFz+dID9fUWFwdy+B9aBzpXzKe+3bo5aN6kBzNLG0mGwH7aKEUOKM0S4QIDAQAB
ox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBDQUA
A4IBAQAh6LZx+VMHMlrvTzE33v9kaq9RpWIgyRGb8otk3kziyg10gRAqtHSkXaan
01sY71+jt6HVgv/um4qaaYsVyO2FWx/FTQf5xaCMpKZE7xVeck7QSKebq2u9jnBx
tzRF4SL5mcb6bX9FeCQTjWxZBj5/3HkWRnEOc/Wva0c257zQK0jEjla4EHesyoh0
kmLZzjqoEy7RyEDrXfirH8Ej+wUTSr6wheaMolRp3WAxkeK7bot4o8m7hD/dRxci
hL0up/65eS71M8VWIp4l99YdMtT3DkPXO4JARETrCIKq0BCESxRgoREWAYyQ19YV
x6P2q0VOe8PnGyy5ufPbbvWroK6+
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_excluded_ok = `-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIUKmG31+ydG9YyJMivYp9ABzmIe9gwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUwWhcNNDAwNjEyMjM0
NDUwWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALLjJ9XNAfJpuRDGAA0u0KNkQ++wZywbPH/EL9zDvjXPlTGTE7JqESv8
A9QMGtkfELsvoVMsP8npuICdEmSLzkgWmS+Dypng2Pj29/3fnxE0cII9WCh6pRg/
WUtfEjF4IShHWuPIlvSg+ucF8peSCm0CenVDWqd+uJ5msXdE0XyyuVUAfycMGzsX
fkiw6q91pEb5Lle+tmBXL8zT+JPvbLDPeHrkU/0+jPwX/xC+ziDHrfh9Hetddcd+
6xJRr72PX5cuQ9lcQvxnSQUTc6PJHascWBkklQxdOvy2blIFTKk8fSZqa6sJP5Qd
cnp1mcvinlpjZ3lgzMtu7TYkX0AnSP8CAwEAAaOBqDCBpTCBjgYDVR0eAQH/BIGD
MIGAoX4wMKQuMCwxCzAJBgNVBAYTAkZPMQ8wDQYDVQQIDAZEZW5pZWQxDDAKBgNV
BAoMA09yZzBKpEgwRjETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixk
ARkWB2V4YW1wbGUxFjAUBgoJkiaJk/IsZAEZFgZkZW5pZWQwEgYDVR0TAQH/BAgw
BgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAQEAOtJkL4GXHbzJsOeLduGb8m99G14+
7ldlQ7zN8/MlkLx1q29ZF3xIWqgRug/mdIdPDkM+E7kmMESwXg832Zbmn4T2DrW1
ZWiAot3TPsI9P3uzHz21gFU+exruc+uNNwoD0rbvV5KEqKg/O6KU/n/1i0wybir1
Hp2HvEUZYKFWfHqbqbfyN+kEUUp0NNWPqoARAcuEr4p5YiFRMSrIu37NfWM2AHWd
fR6it0pc5ynH1UN49J6qwaCEut6pyY/fdzLgHiILdAYcR8fWTLViN+iiSQccUkUR
AeOkf65mEY6s4ul1VUyH+lD+ignUoRs/uIV073pZYxKnD/nAlQZj6o6abA==
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_excluded_ok = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTBaFw00MDAzMDQyMzQ0NTBaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC1wndgO+pMuo9f/a9
xO1yLvJjrq6GWAumFUDP7bV8n2njsSlPjQ/1fNS4LC3V5UCBcwC1a+CgWHd9SrpK
nw0iWRdxQekrbKelwzTihTo2eXgj5wJbEbE7QzrR3jFig0KTgavc5c+jWKLEDG1i
cmCNGC7MTwtwNgt2SmyxAeNa+EDOs1KY/mXCsh/tXLXbhehhtQxCITRfftrAje2q
EVjHyhI0WnMt4q2rf3buRoC087ufyk7G2rDzcghjSn6E0zrFn3HMOm+/7VL0OROr
9g5mDKTAbIOUjiqRYPkeYIjU+M/jyIw9Wn5xSvbcVIgqg3224VES9knrUnZT/EHC
Cg5BAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AKeSM3cbWwPyH09xlKBUrJDdLlVVJIKSchwx9IJk9/2DL3K5/ku8q0GJMIIY8YqS
4Bzi92yiEf/jizZeIrfK/rBIN3jxmx9cGdt0fVq3ZudOEW62ZdK3UsqnINGgv9UE
eCcAySWRZi9qkXDTui/7q7V2FCEJseqwgOI8N9TKxTnwTVyyCi/lyUYz7jOWU/JZ
QUG5HmMBe99z+yaF3JTa0AbeaTcj5urdklL6aOeTcaHEBoUPsTsLQlAYjI/I1XIm
KJlrxfY0DddCLr+CyJVCthLDxNdI70yDz9VNk38amJBoDaCMmQEeYwCZ6jk1d1Cl
bZ1UyIZnvOxXQQQB6+jRcfY=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_excluded_ok = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1MVoXDTM5MTEyNTIzNDQ1MVowPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAva5lDCQyJbOmhGswkMw0
P2GJ9AFxE50BysndmYtslER78rM61UYdVeFKpq/j2oreriCZLbrbrOuMRubGo4Sh
8uoUvxRahVE9aFhKIGtXirV/LNnKjGjvZ0M4XuDfnvheCP+SZsVU36l4LvJ7Dz98
UznLZvx1gUTZsgU69rxd03X/MOh5dTzDzmu01U4U3bhYd8LtCLELfxQVJfh43Rd6
nj1Y3sFmib0J6WI+V0cHKenx+fYjetO5TiJ9Qw3O1hLzDt7EUd1gPgle9jzwD+8n
MpxBdGTyzChAXoBVDgfBV8bxFVzDGyV40+dism8gXdmq3T9GHw/kt1vemWMfnUxZ
gQIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQCwu0rnwQkDndNxQcjgsShz9QDvnDur8H2zy3m9aJLNaFQCnTDx
ZeBEQNeanU7vM53MtdreWQXk9fRZ3kLCP/HxLBcBzu5KDUX55Au3Gtk5/MREXGyV
JksApOfU9sPxaDuhjeBHETkumM1T2CfMO/bzaA1D1zcwjJE9hrVmSmySm6WalcFx
QxCSAIZvWgQIZS8zYf9xTs6oKNFoZLWZZikASUpzRhqx87iLQztOiqO5yVLyNUuf
a59aVQbF7j2plSFoiODXoOF+QKmvD6ATx2OmmnCrM0N2aM8dVm0dLyxsxwUcw9mC
/5ZIq3EF09A56PdGEoaNU0J2bgj/nxQkosIv
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_excluded_rootca = `-----BEGIN CERTIFICATE-----
MIIDsTCCApmgAwIBAgIUciX5Nbh7s6Idfc5QHaSHAKvFqDYwDQYJKoZIhvcNAQEL
BQAwPTELMAkGA1UEBhMCRk8xDzANBgNVBAgMBkRlbmllZDEMMAoGA1UECgwDT3Jn
MQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUxWhcNNDAwNjEyMjM0NDUx
WjA9MQswCQYDVQQGEwJGTzEPMA0GA1UECAwGRGVuaWVkMQwwCgYDVQQKDANPcmcx
DzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMZvcJrRcSl9BxPt4VpAZuXv9AyTWqqbED952LGjng/dKKf3Pjc+v1ySX2/62iiy
TUWuXWOesVZ5tECooT7JZyD0P/67QDgYqjtDYDiJ1SBmaiQ87/w+6hq9B9loyaiK
KniXov0IFHme/yvlUbpa458kXGriV5/oCMlBvnYb1TEZyMcBqyXEluw6CCAJ2FJx
izQubA2nGtg80meLiYoI9OAtDe6ERyb/HRJP0qVlEXQCrDDCC+PK7hMbgNgquFnm
UpLusoNEuacZMQW7gB/Fr0ZWK1HS10pnsf9GYdfR0xU/p6tqBGabcK7HrH7C0pb8
OZLvxdW+HW5L/M34YkutZCkCAwEAAaOBqDCBpTCBjgYDVR0eAQH/BIGDMIGAoX4w
MKQuMCwxCzAJBgNVBAYTAkZPMQ8wDQYDVQQIDAZEZW5pZWQxDDAKBgNVBAoMA09y
ZzBKpEgwRjETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixkARkWB2V4
YW1wbGUxFjAUBgoJkiaJk/IsZAEZFgZkZW5pZWQwEgYDVR0TAQH/BAgwBgEB/wIB
ATANBgkqhkiG9w0BAQsFAAOCAQEAgL7XZUy5U7fzDz3O9bTQcbAxNJ56ky01jJvy
Kj8Wuo+Ot04qO1V7kWF8jB39cwlw9RP2bptUTH6KGS6hJ2LOoYP8WMhOTkHAq/Np
ttNcjWce4KFNs8512URo/8FtQZ4fiFyhKfxLuWS3EX1I8B1OlJVZBsqtCH8rglQM
E0r4HWs5rhBvmD3vgxrFQsdGAN8Tconc769FxaHynySgK6bpsOHe8YWtnO8yCaha
Q68/4dmE3FcafVJT896d9N3w61GvQqsa8jbP2uUMWi3dg6YBqsRU1bh3CvBrYpYl
K0KZZLQ9bTbqH1ksZ9Iod1YeyhCpTd1kf3bkAHDNylqPus2vbw==
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_excluded_rootca = `-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA9MQswCQYDVQQGEwJGTzEP
MA0GA1UECAwGRGVuaWVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RDQTAe
Fw0yMDA2MTcyMzQ0NTFaFw00MDAzMDQyMzQ0NTFaMD8xCzAJBgNVBAYTAkZPMRIw
EAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3ViQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClm2QGf5fZf3Ky+iXjaghW
qJp6L6tDMbMg9yAvA9M60xD6A+ND/1jSlKzPC+95m5oqdvCUXoM7riGCknzuUx77
CE8Usk2bojmEz06mpH46upuLjpQ1tK9sIYODupaT0wx1gj+HRn1p5OuGLFn08MRy
TORY0TdrcGTH5rSlmKrqxjD0fTBUJZh35u5FN6tOTMf3M8/ggOOkksQWW2FdK5eQ
2JcfUxFipyldsqIl9QdFGvybGzaD3MbqTJz0tKX9AA/PWqqC5yP30aS+c6Nt9wBw
bCBu86L6t8nyxGGzY+DwfVUOi6he0Nv48XF647ozDGzO7iyRHulWvfxIQv9P+8Xd
AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBAHgw
O4aO2+WfJWOnOKTTEE7Z4hQkVcrR9Aw30eX8CmNXrCtRzNEvJhhooGl7HX+DzHFZ
BZiUpCG2J5rT4qM3eiNYU15EXZcK7jr2hJeUo6GwR97QXJDqrtVz3ijc1yj3/bFX
kgZ+poFTmK8uktXa940pwuMrVUyyc1UVsSRDyujbogAGJIf6WQDFB14BghDMYvup
TM4PoJcj1AC9wClecTPOSRFX98Ld+Q6LI7sSYS7NwYl9DBZfzvjvoJ7Y81j/uSyY
brVMI3izH0/oOxVDcv/J8T66hfXjxKhaawnWJgz/4Vt95mn0tpSOOuV0nw9dGrIQ
8VfPrcqVUWGjuXmdylI=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_excluded_rootca = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1MVoXDTM5MTEyNTIzNDQ1MVowPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyfIZLyzQT+alQzukkpIX
p2E7wBLQ+ss91sKjZ6OWj+NbWLkaUNyAN76kyPxPgint9p49xjqZY9GCUnGtvWYb
cYZQ1fj3crxt3Rn3qXMDPHUUE3HXJYXBl6wE8paIivqdqoqLdHHgNmfyXURxHuOM
NKcHpBbR7eZPmXVMikz2rD5jesRDZJUYCyRxD0OfeVYaUOX5mNZX10MvNs4WcVoC
TB3/WDPk+PjJKAserOIAi5xJNFaxpILo+iQ+s2+T+ewJA20rro0oLykNKKhvzVnJ
Mrn6gnHavxIoPsFkLUoRxF5vyQ/UJ2+DWsaKKqBDE01LCVjvpd4Z0OVTyU1f42zS
6QIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQAzKKVdTpFjgEmpZy43PFErJVIhLn8iz/a6jAKz80wlVsXhdjtC
4GXPP01KIfzJws1odZ0S/nKVuYZhFCbAudyTcZ+hfG7DOMHXEVjF49QmLh6Rl57z
KZaopWWlkNHtB3jQhdX6I+JeS3hQ9h3ZHg/lp1kxA5FIJx4iUdfEEcHP+VPprsax
NNkJhyMPXhEmzZkhBVwAriAsmaoPAhw0i8p706GoyPEXTTMkozckX846Zo1VKJpG
ko3gpLlcY/eyBDBN6wdoRWatA5hOaMrsArlOPwFnoIhWs5PI+drUiBTGEpoFgRAT
HCBEKADPXWJ3oEDPlvIN+Q6VsTHMskcjFWVe
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_excluded_subca = `-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIUFsSJpy7YvFGg4UPXR5J7xRF5ur8wDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUxWhcNNDAwNjEyMjM0
NDUxWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMNsQN73YR/WaK4LNvwHZ4saV602YIRW86DObnWz52OtxO+jnoysFN1H
T7YuyZziDGgN8Cbo4n3ERb3QuhAbaPUdeMZGeikLp9eb6043O6Bs9WDwspXlsUXx
/ngyBbeNB4DOqKyEwU5QAqWjpUbylpMXjNAaEQOU02BIFkIxCD/O0s4oZN6DFskc
3rwy8IYZduCeVNXVswdim2afo0tuhU0FNyrDBgAcCwNeyUKurCnVD4QF+XP8q1aC
LyoieXHjTOg7l4Ksa+VOyTMH0d9qzRrOcOQm78DPHefsAtBLfVaNWHMsUYWz0S0z
8BOFDzew2dGQa/d4DbjG75S9DkbvwC0CAwEAAaOBqDCBpTCBjgYDVR0eAQH/BIGD
MIGAoX4wMKQuMCwxCzAJBgNVBAYTAkZPMQ8wDQYDVQQIDAZEZW5pZWQxDDAKBgNV
BAoMA09yZzBKpEgwRjETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixk
ARkWB2V4YW1wbGUxFjAUBgoJkiaJk/IsZAEZFgZkZW5pZWQwEgYDVR0TAQH/BAgw
BgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAQEAcUxARhOit2At4mUA5hrKmljssLwP
995QU6+645W0J7gxv487aawalithORk7zE8wm4BAB7mz4S6R8UdfNNY39pLEfh7h
JiTH5HUYqfolmT0GUTzvUtBCE8fkIf+IX5bVxPgNrEIAT6euJScpJkXlqr5ZuYts
EHSlKvgxBDbddgjs6N6OyXQSG6Po/4PpcgzhxKy8w2qfO3S4j1G5YEWwQBRFa5VJ
c4DNSz7ydRtkga4VDsIV0mbK0mjZeJDu+nb0V/rsyryvkZj9qSiH3M9y/3gfvFWD
GnifjahHwYe/xN4eNSgSxgqYx20TH4nthaFQgcDzIpqSmJfOHHCMNcg2JA==
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_excluded_subca = `-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTFaFw00MDAzMDQyMzQ0NTFaMDwxCzAJBgNVBAYTAkZP
MQ8wDQYDVQQIDAZEZW5pZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3ViQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUc2Muxik2k7dasG1BBksQ
5M5EPCc101nS6RZgD+LfpQl9/DD4qHZF8iMdGcaDg531wVfchlpejpsE9ghHsHrS
YHi4sfw2Puc1sMoJ19WDdOmAA3uWzfLUGp0T0jx9vifcElKgmczvUucAaHPLSK/O
MUafIABY0zOatVOBdB7XzfctQQQ2y5VgegLCDSPP5YXbzxernczSlF32q6pDPO83
Z8AfQmosRLsFL6w0iMtfcdeXzUuEh0n+mv32Gbg7zNORTzQK5PtO58LSyJoNO3Gn
gopjYInUYRd6dnI6QXfaS7vE0cVgnzXVRgtKoroIEbVs+XNrtqX3X0bg7pXSsCIn
AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEBAB9E
GDcUX7KxUsIYfJQYnNIQIcFp9lcYIv8H5Xt1o5ZhNRYAOaRLTsdjQaB/nhiygwZS
eij+V935kAmcl0V0UWhb+W0a18kmPSWH+AHXElMfLXKzYabb5YA3EgiiuGV4uxBD
b3Wch++73P4m6AjApDaYG2MOFvoZuvmPNi5jGA+fGsxMe1gBoKmg1Z9QnGPQF1yB
/M9YJAL/qafrbHY7IyliCLMXgfMXRjXVCHSYwLuPfkXH5QIx4Ihks7NVVziNH/Kd
AqXUU8j8kU654PNggTJ23aar3JuRK0r1XOchG7z3YvUFK2O5Eov/Y7Z6FEjs4oK3
IwfESSS3nPVZijufvbU=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_excluded_subca = `-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIBATANBgkqhkiG9w0BAQ0FADA8MQswCQYDVQQGEwJGTzEP
MA0GA1UECAwGRGVuaWVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNBMB4X
DTIwMDYxNzIzNDQ1MVoXDTM5MTEyNTIzNDQ1MVowPjELMAkGA1UEBhMCRk8xEjAQ
BgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFmMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0jyOWMwIUsUif4UqnIkA4JJF
mN781Pn1cnOMTmXuBmmxb1CUJEmj45ZgaAWuYH5fokrH4CB7hNYQN6yDfhnZDfjJ
dFo/6d359qRYaUxnj8OuHx1HtqVDVeF/BiOXbBCBUwEhkpPg9yEBensgY12peeCU
ESOEjOffQDMsJXK7Ewavdbz1Zggy5hkL3fS1ToLd+QSsYCWNNdUSIhYhtwt+ebVO
BdwANOPPpFjtd4+TWf/4Hr/hXy6hv+XUFRrAxUiiKcwPQW/hcHQY6P/91gyRYPOv
9rREex3hjP9+czq/dDO6gwpGrBIeG0N+ubi1j7Qm2VGxpxGOQ90bpUqv7SsJ1QID
AQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEB
DQUAA4IBAQB7njnf8EvV6Ks5jr8Jp2rLkKnKkiVHy0jo3tb2zlpqBHSoE0AjB7BO
Y9u0gN41YTSBDDEt4XYNB8zdgcykF7CjtkyjA5XZFrd746mtV4B14obUI9flUOGD
LQSvzsfQ8ZQXI3pODwKw5h4c4Oamd0PWxDH9cdOJ6gYQSYLvGTJ3Lw7mtLA8/FHz
iud7q4A7IzWqc4ddz1fgidA84PdEQuueIxe+f+dIEg0xbmx1WDE1M+DODNoJv1lO
0WJmtih1vXrMXZmRYrX+C6hpwe8eEUZ8I+ji166BE77c8WuVOVv8Xt9/VgbbfcV5
Yks9b1uKfoT2OFIZpWz2Koelx2QY3hXV
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_excluded_leaf = `-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIUER/ZnG2p8SujBgP67sNKnIsmpIMwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUxWhcNNDAwNjEyMjM0
NDUxWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMouJboGH9bOAMsx/PX4D2tCay0+eWFrsN16XIoXy7E2ARjFzzEmKZPD
WaaMhFlNKP2qO/6pD5g2PY8I27nnyqmzXoz26NJ7e8H7fT7wmbrEcLHT4ish+X3E
NKxKkTG3SFNoAlCaTZvf6QhSMDcAsG5tEV1MotVo0xwrhITzbrOwejnn018OZJ21
CPK7mFPqCx6MF4gfzzGG2gTbNU9K4AjL0ykUAKRBs0oZ/Q/Qe9Iid6VW8A1+qUZT
lJ5WjxYgHyaeW0dlNAHhrnpo8bY0nZpvIoMisGJKSbyvp/HO1Om3mX3PfUjfi51u
pS5GUKQ/a/rvCu6kKeK3UU6U9eI1TfsCAwEAAaOBqDCBpTCBjgYDVR0eAQH/BIGD
MIGAoX4wMKQuMCwxCzAJBgNVBAYTAkZPMQ8wDQYDVQQIDAZEZW5pZWQxDDAKBgNV
BAoMA09yZzBKpEgwRjETMBEGCgmSJomT8ixkARkWA2NvbTEXMBUGCgmSJomT8ixk
ARkWB2V4YW1wbGUxFjAUBgoJkiaJk/IsZAEZFgZkZW5pZWQwEgYDVR0TAQH/BAgw
BgEB/wIBATANBgkqhkiG9w0BAQsFAAOCAQEASdeIWexo2e4JTIwEpa+Eq2LZL1+M
MO14ddKsVs4xXi/t0W2XCf3CA9OCSeLXQmPipS7y3VJ9XGjUwMIKJyuwpXTFQ4g8
D7t0eNfBlROIFSqDGhit0W0A6h8sTUKG+xfBhLCDmp3Y77Ma8ZzdTStCRyuP9Phf
5J7qXnQR3mJYxcU3rZ5aI5pJ90K7pQTHzvqqgKdLdvPxXuo6hATXxrO7LQGbZY6m
4LD0bZc/PnAYkz1XKL8qwDy+/J+00DaaAqCkKeaT/DwikI8YKCN8V6VsXLmiXFO+
y4ms6r+xEIRrWn6Bu9qdXN+R93uuIupzGVn5MorKpXOIIpg5FnfJmhREfw==
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_excluded_leaf = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTJaFw00MDAzMDQyMzQ0NTJaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkt+0vVGmZja1qEIPG
38tPtiKup2eZPRBwj6gwyZQgBrLn+/U5UcDiO1sfoNpCE9KHGxl2eiUZGirsahSA
gkS9Qs+zawQ9GPqh0btZ0KfzIzMYOjiD18rPSlqq/LJ5PILLt8Z3uYaeJYM9YOXI
biiGaAN7dPaht2iW92l+VIbHgEjEWpHU2ds2kEJmm848w35hoPsHuWxRYaLPr2va
XGAoiUSbuxNclXRTIm30xIosmGTPeBxrdJ5YH/uiVgfvaNFiQkbjNrEWt4b1DVwJ
mjB6o4XyX5mWI6Nu3ik05FXe7gYAfekjV+UeH0JcI/CW9q69gsHfx4suphA6KRSp
vidPAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AKEgKNLBlpbRGbIV9e6e3ma9lEn6x7QpHfFLXGajDznH6Yl/p4NKjqlQu0eQECzZ
em6cHze6sI2UNXPbHnfvDHSytdR5HPJB5NlWQ+ChTHw9aTGiscdYpQx8FmGQNLh/
ksdP5xaopCNcqEI1MdhjDzfy2yTjIpxe228nZPpJ6uufWhXogyOLRiES/flztuHQ
qn7HXTMRf8PL5L/XLK/W+g51j8lToIphAts1wWACBag+LVBexFBf9yWIm25A0V7C
Dzpqf3WexKIUoPeE+Aopuxp+GyCEBWOV4XNyTtQFuQRGPBm9yb9FoV1YRHJ9EQoM
7nnDEO5bB3baJR44wI7Y9ZI=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_excluded_leaf = `-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1MloXDTM5MTEyNTIzNDQ1MlowOzELMAkGA1UEBhMCRk8x
DzANBgNVBAgMBkRlbmllZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFmMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwU4n8x5VIRYEoAvc6aUtNMLZ
RLCScHDt6xrh0irM9jeMCKZeIlm2rfwj9NMMy6amHYXcIFfPWnFKQVMIvDicNS3Y
4bTW4JeaXqyIRcTexwXP3tTJriHCwwPx/pCtBXplMEB+3xQ2kWJMLmrQ5+nSGo72
EbnSZPb69AhYFW9R0MqqsP5jNEfJDkTHubiEY1ceZSXujRkntCsw203e75I066Rr
quA5a/OW8kPHXqwBJOr0UopE6bxisFdbbSSQB3FOtB+qlxXnt78ruE8bJA3shrAQ
70hcWvo03xh0UKSRjtnd+dXntY0ayOLBkG3eKXIUT+bUVXgx7RAm0FERFJBNAQID
AQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEB
DQUAA4IBAQBMm5kHxsfwI5u3QoPdrYgbkUtejeJqrU3FpWGyn/covE82DabM8znR
ZFXCol+vDKPFUQM0E4b9Z08cJyCnj88GokhanBWio4hkkRMN5KoolsrfPCRy2CSw
cnbocsytyUj9sGVKedZCjwS7X4M+I+eTm+U2xTjF57BzsHqPBegX+Ofrj1SjxRLH
xBHNPCbcUJ+cvOOrRAf55p2mqrC7Q6fgClKC+fXAOtoqz/ZxZaD0PKbZlQCNWAkv
O9ec3/SAIOo6VB2dq99ipEeLOMDzFgIMAzqMcoLWJzyoeLk+QiMSfX0QyUP/6J2F
vYRU3G452BEcPAgk1NW0pvVP5aJDh3Ep
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_permitted_excluded_OK = `-----BEGIN CERTIFICATE-----
MIIEBjCCAu6gAwIBAgIUHHkAQg5TrY3k+UsAX2bN+Tmcn9QwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUyWhcNNDAwNjEyMjM0
NDUyWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAPD++dF1edxTqT0NoB33VdRMJBvl2MNvs1dDpxN1GDzGmqyHIrOZZbjo
k7xQhGoWBsqFS9Erz1o8li70l4ZC2yG7oQPTVqMGWMGza07GVK/jN4fT+qwTCT3+
P7X7i/D8UahwvnELlt6GxnNIpSY/vdQ4A8Cm9Xj5WpZ7hbsR6Bo5S8Zh7zzl0SAR
pkZ0ImtC//9+VbYh4LjHndQhGtyKBmL42J1yl4Adll2NvbNTVS3GU1CL8d3DVay3
IQ9T9adR8MMH6JcwZqrMoqOTRYarMxe+PyhRHAQJ+bWjunidInrKDpMltWSIbB56
LIXf0bYghMm8l5K1anG4LnLT7bnpLB8CAwEAAaOB9zCB9DCB3QYDVR0eAQH/BIHS
MIHPoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkoUYwRKRC
MEAxCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09y
ZzEPMA0GA1UECwwGRGVuaWVkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcN
AQELBQADggEBACBb5Z5bO8kRXwBZ5X45CCibEzXFIlCGT/ltx4pwYwjizu22zHOS
bh90opvy22DYS3CPdh5ymw399MW6w9eBGEKMF9vMAaO4ilM+Q2M1LpLtXfQ/42Pl
I++5UAQX30NdbO8yipt0gX4Iu+GkbTnrw5yk/+t8i0z69BEMhfazj7m/u4sv0ut/
HGHX2fwQvOiBRkj49MlBlIWV0DZL5ElpvQHj7RdQSvn4NW47jr33sOkRaupCpI5b
tflSTzc2EAMFuZdCGAoXFOMUqij3YiHWSU6UYPkQBli8uD1vYPSViap+WT8AeiFv
OeTzR443icXmzlf4wxl9jsTHGfRADhvLciY=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_permitted_excluded_OK = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTJaFw00MDAzMDQyMzQ0NTJaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY5bIR8o7qsn4csuqR
7aeg266455zodK93EMNRUA5MMVa2dSTJYigNvkgrxJZtcftG6Wee6Ggnvd6AO8wC
pigLog7VEsH4eMU65BEZ4qafTKoRZm/N4I2JcApaL6DswSdvTjyPS6BNzFYvgnoc
cd/ohhqpIDTxlMQRC5tLWY3JDdN7M3azAdVW3wdaS7ED9jzgBCoM/r95VXSlsBss
4N2lLQ0Kiws1znbRsIv1YbMMTwcSAoGuCyQ7oRHvXicx3Uvuqmmkqvvx4XNfHyKd
C3MkxSynxeYBMnEOqVgsHd0UfxY/eiWUvpNQAUJErp3kQ8a7JWve8/R7OMJnr78u
mwITAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AHuotykffPrlv2U5tRH3ld+05d4Hg+O9hehwRpIFl/8bbCE1ODLMM59RilDgvp5m
hdsS5R/Ml3PyuuLvYG3X97MjWs7GgKrg/ujBFYR+NboiAgdmwxmJ8VofoHwnkoJH
Hkdz7BLuP/fxZ1by11I+VqIYzcGhGq2RvUwLv2njF4+hllPuZ2omHbbIFI6poDfS
ra0KukiyYcxxZkusKvURYnHwA1v7hTbGwnK9nSQnLdpd0PXvGj5L5x+OHTExywzf
hZ5Vr0ypm3R7sRWY//+CdfHYrRzlyGV8noM+O1ChM+WVTW/GN/TFfirH2HP40Npr
AGqLZQf2YoJszdfGQx13tX4=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_permitted_excluded_OK = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1MloXDTM5MTEyNTIzNDQ1MlowPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvij2deQVA9eQoL7ub3M
KVMOyeab9ykDgwwGv8QUaEbhd7ceWRK2JTl52G/H2Fvjs5dL3Qs2xQg+A6J/cYdF
FwmJAcueD9UBXf6FjLmMVpkWHnRWb88lNCaiTkICxgBClCL1gXjdJmADc8JYMYMU
Oe6wRryR7hU9pAfvv/b5Af+PX9yZCVU0W+sV33E4RLsxXh00WwvSATAZrKJAyNH8
d3mAisKLPxiGoe8ScRM79QXseCmN2DyU+haH0gJQ53/P7E8bjyE93V1uzcTZ1Y4g
qZJn2U8OddcfXlaQrtXKaTK7M7ew7IK/0BDtEKVHuq00Rw06MAlJC3ZtFkVz7b7J
uQIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQBECiF98p9q6xsjb7tVFm3M7o2CcZz41rfI5uqNygL0NhJ/UAKL
uMRJAX8uZryAY43eDyENV8pG6E9eD1igicfOhHM6OOfYpVsKp4mGqolsJ+4LY+Xf
OBK6YCb7E0XxKm3Jd+BwbTZzAQREHAszs2DExtRnKSqVadK5iibuBiTqj7z2uQs2
IagL8eosXur1YlAofPsOcYY2F3pGLuUOarrGhG6pG3Zk4hIrRMSityydRUtPP5s0
BrkIuCAbQfUNNvZTTZHe3lGx0NS6dKZEifv0sNa9r7LE3P//3/ygMrdySnJdIWmQ
Fos0rNtOdCQiGF9A0GEe8+x8XvSQIduzO/bP
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_permitted_excluded_rootca = `-----BEGIN CERTIFICATE-----
MIIEKDCCAxCgAwIBAgIUN/OCI30gBFPmRoocQis4QA5OEpkwDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQLDAZEZW5pZWQxDzANBgNVBAMMBlJvb3RDQTAeFw0yMDA2MTcy
MzQ0NTJaFw00MDA2MTIyMzQ0NTJaMFExCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQ
ZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEPMA0GA1UECwwGRGVuaWVkMQ8wDQYDVQQD
DAZSb290Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJalqWEi1E
6bWCCprS19c9IFSnlJdap0XAf1tMATraZ+PA9Tln59hXgCeerfOj5juSK7cVmBF2
WADibScC8gAa//QxOsrUzIR9HEmxDU0dk2Ky6+5dsGureyH6KN0ODJb0igXjo24V
t6pLyWugb/VHUhe3bSPO9tp41UiUe27RDuTKQs43DstM/i5HpAcZ6C7UGKE4JWNR
5/09qQdVWyDPllVC1kHP8lmFJMiHFpJQLu97jFKimIlsJRi0FzhEZ4bstSdhvv9g
JbR6Lf6vCl4KZx0SbAb4fgwoPMhxhshiIbwQg1R76kQCkH8n8k26+p4piN7Mk/yk
WWuZv+T9l6YxAgMBAAGjgfcwgfQwgd0GA1UdHgEB/wSB0jCBz6CBhDAzpDEwLzEL
MAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnME2k
SzBJMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBs
ZTEZMBcGCgmSJomT8ixkARkWCXBlcm1pdHRlZKFGMESkQjBAMQswCQYDVQQGEwJG
TzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAsMBkRl
bmllZDASBgNVHRMBAf8ECDAGAQH/AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQClCGBJ
fpzdwvHOA6J7g0AI9Dfd2pgVKlnlpg5el+atQsBobOgP4qLbvMku6xV9pDpGqh9d
tVhTyOzlEU3VKU3CRXA3m7VYlJsQ/KSjaAgxrw/d5xMlTVE8nH9LXGFvysCaZPMN
X3vW3NLGpagZF7NOLsq0QdlUsBcebLLN8ylpBprhdzu8gJimsfi2kqK62bLfd/fn
z7T02A6mz5+Wsc94SkYaGlxRkzUeOzTa9OobWRPgwWOY0vxLcmuEOtXDAQEU8FKa
oMeBUF7ioKlpFwWgDBcvqACu4NypB21fal/udhPDf54s0UMk6SDgAVSHCtA+fkYO
yvfJQWyYi1FqKLYa
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_permitted_excluded_rootca = `-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIBATANBgkqhkiG9w0BAQ0FADBRMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAsMBkRlbmll
ZDEPMA0GA1UEAwwGUm9vdENBMB4XDTIwMDYxNzIzNDQ1MloXDTQwMDMwNDIzNDQ1
MlowPzELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ4wDAYDVQQDDAVTdWJDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMsVBEbP1/GskjZsqqLA8gh3e3EOTK//OiATz41UNK3VI1e5Rkc8AO8M5ZMj
SmRdxp04eXPP6MDOjKKOj4rQNH2UdGXi/nsMeYguvaQNamiUoipcsxrkNiYaiAR4
W7CpilV3g0O3X8nvTnN7FjVZ0JAoJeG/I/yEjRIZpbLZK6H52dsV0lic5MPNvEYu
Ev0TWQms4cqzDnzKg0/XKwjFvAX7kv6z1uvvip4JvDdlmYr6UKP2wZ7HBbMnOzyj
ZViF/gCePufpkkFmKYC7rNtqVnVVt+xqVPX6uq5jyGueEybZCuCgPlnbmKPqVWOW
clkMVl/3B4qLM4icdFEt+L3E6PsCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQ0FAAOCAQEASDjFeGGAGFvvSgGjUzWfSURoqqKc1NzokXYBcvKs
XWLKXufRPeZWgEb87+QlSIQsd+punSEpPIlCWxGz/5iXS99YDU4enWgpZBB9mKnb
Y1MZWOTEYRAptuQ11Aw74do991unNyxFhUNBmNP2Vd8VP9ezLiKSoSxsRKStcVlv
OERLF9MILFmTQh/F2mV0nm4EbTsPhdkmdP7fG9hKKiVKyVQ+7VNo02APfibz2Bdb
zANfoW8iBqSqOEfaiQ87ZlNYgR9HX+0wQRotEEo2nRaj8zWc7q4cf2CrpSpnwMzf
vTEH4jCyq1Grw731lAAjvC6dLgdu4StYXMm5VX58GJq3Ng==
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_permitted_excluded_rootca = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1M1oXDTM5MTEyNTIzNDQ1M1owPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5OyPa7p78CQX2ZwiT01
fhIgQGqTBfmQWQSQKBvYySCNTFnVBeeNxdYcHJRPlemYTJwva0S/z4zsJx2snpXW
ukB2CARUQxWrvT4soJ6f0R9UKFj21vefanvZn9P3zERzFji1QpuvYelqzNtalS/d
7rQmaNkqH4vgLFe2rl+mZeQBjHsFd4wlMU0PBNTEO+RScpY2jjcbBTBq1YMRLeFd
6FplGeWlSQCmYZD4HCBzzn/BEE0xRHNYB4ez39byPR7p0+AszRSdz0K7+OF/aTha
XChq7fMCk8Zh+4plKRvOh3LCCsc+cjHxK8CPHAU9XArM9r4QG4qmXamsLeYmZPxk
5QIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQBNiY3fPOBhrO5sB6m2Nd+UvbZjHnnSF5Jr3J5a8+/vIvFk/VVa
SsKVMxVgeQCcFsl8XSdJ0tGAlUKDpHUysUxsORCeqGMERlMTVBOEYnxf/zSo11Ib
MSRoRg61HdFLrXOW7w+DC5gvml8sp5qtD6C49WuppkcMk9eG7MwquwPyy00RR+Rh
d8gZeAg9/S3pHJIlD9knOsJdjXSnSsI9Y/f4l6/DWix45LZSsgNTOY6kNShiymq6
r0LNUsrf4EXHfT09ue0G7wM+jFNKce9/jVODd32RlauwoELCmZDn/NNE1fmgM94B
x3TmGdDmchE4ohuAxsd3QS/eP3fzCjSVUxWz
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_permitted_excluded_subca = `-----BEGIN CERTIFICATE-----
MIIEBjCCAu6gAwIBAgIUZoGLxoJB/t62La/s4Lz3rPlJeqUwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUzWhcNNDAwNjEyMjM0
NDUzWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBANe1PwY2H1aiQ/I4x895MemeNJ6FSesXTwuVXAnfs1bq+bKnqQD7CLzO
edaBtmMZA7YRG/GFzUKcsBQpaHoGUqLOQ89Uz+JtjVzeE5ytqoUUfd7YxEphmNZV
Jh/yNqyoOoLQWs5ip5rNKPZgENTt2EiPZUrUFsuBs/drbla8ZJoF8w17wLhneanF
TlydJvnzUtqhtXV/qclMIbqi+CjGyIHtaQORR41nXu8JIEjzlZEUgarLZ4nAqU2q
3NhBJ03AaklcibAAXEy5OxYF9jV2+1gkkA0xFMB0Rt0JyhiC3E6QH/m+PjkCrKhM
tnw/mtrLAAsAaIP4t4a7HvXViWrckK8CAwEAAaOB9zCB9DCB3QYDVR0eAQH/BIHS
MIHPoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkoUYwRKRC
MEAxCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09y
ZzEPMA0GA1UECwwGRGVuaWVkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcN
AQELBQADggEBAE6Qfh/vmiCdpYXtQe9IlFZeH4429HPgGJ2rEo42kBt7BlDffH2+
8hfMW8TDMrIhnQqNLfOCr1wY5xybnXdURcoB4apjN1weFxsvAqJCAOXKHD/z1EHB
gyxwfNsUbzTfsMgX4ofa7OAKxhFDy3MVFnFQZsh2AWOwwr0t/abmw8fbeQzzyu+/
r0yFyPEc3nnX7SYVVoWyHf+yZg4OSDcHe7kazuHoGfbPEjLFsAdIORRVSzt3dSta
6/uhtKinfChOPdyk8yQB2uD2sE/UW1NLwQjm1r87eea38M31+UCAEhRqJXy3Gijj
+ntI1SF2rRUD0AKt08pKnhbcoPtC4ghZFw8=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_permitted_excluded_subca = `-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTNaFw00MDAzMDQyMzQ0NTNaMFAxCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEPMA0GA1UECwwGRGVu
aWVkMQ4wDAYDVQQDDAVTdWJDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAM3MbMOK0Hg6jMpQInol99Qo81sG4zTkDbLUwusvpurLLLCrzOsidf2Pxrv+
nrCw+mLfCKE1h953FQnE25C84ZGIInLDhVhOYWApzPxft+qOEBYA9UQm36gRrg+I
+1vERD0MPVzEGo4X1XkcWahlYoNLE9yvIGLNM2wTi+tcaFOnqclFWlVMpHlpaOO5
9UGsPZcqBO3EDP4pFGBc/c8NPvIayqnWt3xVie0CweYR9R42TR6wa5zBYbXN6QBX
qdJSVz6CyBT9dLQpAMAVGErEKLI09FtdAkjfkrIpJLOovzmOmXKgGW23B1shPc69
GQ/amkJ7rSv9xf8Fexe+hx08risCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zAN
BgkqhkiG9w0BAQ0FAAOCAQEAYpQNA3tDt8wjI01RaJuJD2qj+mGY3Awm6rhGEuPD
FbrR6Tx0BmuVXBFgBc0HkKvx2VL0MIzJ40sekl/4RPtHm1x7TIR0U/doqG1npEPk
V+YIQE2lwjhsJNH+yxYqQKhPd0aHrI2JMbeURuJURMlqXJ2P0wM/no9z4+7r2fmk
Voe4Yek22geOiyBo2Y1Gl7CyvPMuVJOBuzjssu8vciVYLaoEaQO49w++nfcq/8mr
ToDTThwne5AESDXi7ioyIMM7N+8SLlAB0xu0ElpgEqAvTZzYWDDu1rNKnGFghYgA
+GVcVI2E9k/eYD+wMR/5aCn+311HRUh7HorJhpr82JFElg==
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_permitted_excluded_subca = `-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBQMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAsMBkRlbmll
ZDEOMAwGA1UEAwwFU3ViQ0EwHhcNMjAwNjE3MjM0NDUzWhcNMzkxMTI1MjM0NDUz
WjA+MQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANP
cmcxDTALBgNVBAMMBExlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDTMfU76XQ0fRzY2vuNEcB8FMO4Z1el2DoQHpp8FmvrCzd22PDU7KmnrPI9GJbD
oNZi644yKGS0MsoAyPvXwz+DxvxeI8vEz+VMSHWYR3bCyBcnTXurjDQpjXvlmmCK
nljgYrg8JAw1kirpGYbAV+QEOU+mdxdS/99Ux/Gn8WT2XwkGdhbZq53R6v4t9t2e
4lO45sS+uVadhOfKyKERtQj9n87gxjHw0E4LmxkxMAkWllYWPIVFpcVM9XwvkM+1
QLm+5alXt9h7UG0WcsC7fuP2eoBmZ9f9isT1cj7+S8cckZ3NsY2AoEMm3Gueza5l
HxEJY0VB9rJNGww6bILt1fcvAgMBAAGjHzAdMBsGA1UdEQQUMBKCEGxlYWYuZXhh
bXBsZS5jb20wDQYJKoZIhvcNAQENBQADggEBAESBbtTpdEbrJPPKrc+FVCcC+nPD
EMT6FQgnlZvplz0AuMlZvQ8LeSaS2onDy6BwOrFiZF2tLOz3X14WS/L9p0fMZn9H
Xxei1iR1rOlZaV+wUaLlpKFjbdrs2Y/6+586ikymnCLETnev66JVrcDth67Q7cqO
588kio1lWkbhaaIzkB8U/vEEzXWZX/b5OmZtp+F407DPK67Ubu37v9FZ5h/8M7t2
MRKP0OEWOOCk25WCMWpQrWj4WSjcukUykuG8H/B1XN9fij4vE48UGORxY+DpzR81
u82w8+dHO2+vc5bazKvO4kIK1l5bApcpEZdx+7G27dN3fN1IFEHh7q3Vu94=
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_permitted_excluded_leaf = `-----BEGIN CERTIFICATE-----
MIIEBjCCAu6gAwIBAgIUZ/AwWIImSJMUCRlk+v3NcAx9wpIwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE3MjM0NDUzWhcNNDAwNjEyMjM0
NDUzWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAL6ZyXjgtDCmhyY+Bylm+hwfcR6Mmh1xZUV/zv/3pmejlPuqktdIjFKg
Ja3w9bTrgct+U/ugD014b4zNHiwQlWGzDL/zynB1/STJFWzNKwtYBclQhTqZX3fs
e4c6d2bnbe6BXghRQ/qxiknmAIJIfI4DhcLZTcQ3nQe09P1oxJQM4+MMWR9c8tnN
3jeqrVUUDpatVL2VLuaoYDStvxyeiKcJ9psZ5aFv5hALbx414PGKkiyOnZnHqmuB
92wzHv6PGihdViPmV3RbnQEqpcYNKA/uuLZr11rfxRfvwu5HsTDaps7BTTUseT/1
jucBG86Y7qZWHAUGLXhgXGj8W+oDHOECAwEAAaOB9zCB9DCB3QYDVR0eAQH/BIHS
MIHPoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkoUYwRKRC
MEAxCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09y
ZzEPMA0GA1UECwwGRGVuaWVkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcN
AQELBQADggEBAIvfjB5gfRUo1IXnzQwbYCkONLZUHT4hlQTtuEYZbRlt0JKdgmmg
TGqyzdtfsp2I2ph0DfVEaLRT86zRsl/w7oXx42JSWiAfcF+vE+2pVVT7mjMKEm4k
A3GAt5h5Ob+5mMj1rBgAxIPa74K2qVWVQGReIJkmkLUYiMwRHgvdSIgE/1ysuu7d
2GrE94s98AGRmLtHVVAYC3+aMf2Pg3/0gcPBG+LKw9ZPbjKFTxPOJy5Uoc+r/UFl
61rhY9wqsjfiaGA7nPzZPeFcwlBWL1DRW5MMOp2xl3epDkluo6MW5aNFunAsF7IG
48G6IU60NnEUfhVD15f34sIjmYu57vQU6j4=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_permitted_excluded_leaf = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTcyMzQ0NTNaFw00MDAzMDQyMzQ0NTNaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCk66g519/o7Z1ZqIz8
3ZC5794Vhe3pP2LgixfaFslNnSaL+8Jw0mQzVPNS7KWjK2wuc3a4dKWfAEff++Bj
BKCfNiZhRo4B7F1cycSS2h0H2Hs/CiB2FjECdVGwE8vaPJ3I+IllyHD0pNu2W3kZ
Dq24HHeIiPaViSaGAYRwXm3AamZxaWrUyfmf1TQcNZaU3BgyFerE2Oq2yMN5FifG
NDd63kjXA3tLHiihBOFHnZ+SsOvldeGO4HgGYrHh05qomBX2t4zkoJu25lMN5KSX
6y8k7yuRpYA95LYcj7+rOEdtcxugBX+2xDVH+to9SmV1Tbksc6AlKuULKMaQs731
8NhnAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQENBQADggEB
AGbNb6n7zNuV59aQlg2h6/BxfEakRqRCIuZugjmTGpJyQrGs0srZW+TZ26pTm50J
8jpTje0IeKiR5tm9TiHLjb/vCP70Ax4gyl5GxxsWL68uURhdr11E5FtUEz53VJGD
qJAzUlIS03Dxt2iri3UmpwHmOJ+2fQeoyUOYxCLXxNHOcYKC5M+c0KpHyve/sPp4
hqv3Bbh7hOVMyO7Pp1VdxUUdXRI1uCIC5SvME9+/PCYRcPhURNIp220IyMhGQAsj
t6hPoqywJJMtdvEEJF2U/cnQkcEfG6K4vMo9UNXSSsSsVf5LkvMUOApNj5Ix6QdH
6vMbY3mqAKmbZIG69Xn88VQ=
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_permitted_excluded_leaf = `-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxNzIzNDQ1NFoXDTM5MTEyNTIzNDQ1NFowTzELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ8wDQYDVQQLDAZEZW5p
ZWQxDTALBgNVBAMMBExlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQC/8TMEC7sZFol4Mq3lGOfrSsn0wKJ2pXfCSOH9fddBtbyev+SDMRO1kpgvUIbF
i76hFhh0TGxWv3gqHf4ducn2SaY6txFJ2KnkRsFh3a3OjJQolh3cM2tgH4dLKr3b
Ig9AkicN2cnE25LMA1k5cUOgioDUSF1slvj5vKPZLEPSJROYjkcqYjQoz40OOPcg
gzhX6gdnDJIIQ0fuhPxTB4XqUDLQaAAJAFXJlEqbppJ4UUIEAcScRjohl5ev+xNE
5oGoJAgf2t5fnRnDJ4Xc9Gf4UdntgO3L6+9Lb7UR3xqfYVrqb5uxXkNSJTLaHsSo
Sigzs5Z2yjNTf3C6jUbvpGtnAgMBAAGjHzAdMBsGA1UdEQQUMBKCEGxlYWYuZXhh
bXBsZS5jb20wDQYJKoZIhvcNAQENBQADggEBAAKx/WzBwH+Ct+OFLfhubUCBN7+8
LSJykUzzhxwHsvz1Wznl8HtnaveZfsT4Jy2TVSYtq9Uw//QSkbE7T5GNgUVgJX8F
wy4N/r3oe5FhHM9+3Gt/Y2emk57TGwYKNH3CkLLV49HU9ZAVs4zduTnIh5GEq5ME
fe/nED3uMLG8hjoJcbkFrPM93tDAUvECFj3CT6T3Tkkgayl5ne6ze6SpkptLnDz9
QqNkHVN1AabOnotzBLhoQ377aY+IulXI5nTPLCqOsoc/25sseQ3MUcz8gPGDdad5
LTr5PR1yDHhapT53uuEphwmgx5/LGSRpS17xVBcN49dBcRDH+7Y9jaJx4UI=
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_subca_restr_ok = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUdgdVSerl539uQkUf2PkVF8xeZY8wDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE4MDEyODIzWhcNNDAwNjEzMDEy
ODIzWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAOr1t17VOPHNQOZ1Cz9WGmryTmqP0DFOYpEapxoJ0mZtAfZ286Y649vb
Fu9TKaGy8cPkwOfDfFlyh68kfMi2SiJxU7b0ETyBdkI01fRlbUgzq043etDkPh+L
5Q3EGwd9nhQHwzPUKZFgk8x56wYW7lWcRV6wEiqpUegZYXdvuCzKaCMy8v3lFP1V
hPDWjTS/eudfUbsFgjZjtwy/DjzeMT7EmbmNafTRV0xJuc1+sjr5omSXLafH5zkZ
BqAbqbBpUEPuHncgAKUpjIpwkzJZlJ/WjzZIBCH0mQMoMUiOMEs2FqGvSpOCcYHd
sEtSBeJvy96j+dNsJkiB0V8ns4rEO6cCAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAJi4InxaMxsNPnj9z+GI
1O3W6oofqQTm44+jYiwS6IGAw9fSp44HHbRigT1g2hGgz1T1FHJ1X2GbjakxQ25W
IGr0QDDMA5zYFjnX6NsNEpGcbg4HxAyaoC8HVhgI9xLNkHGZ2Qy/TJw0zcY2BlDZ
h42tTHc4pWzxyzx3o+nSxddqfJG0+xrOA9Y5NmSLOg2sRsdEETlOC8Zng+wZW8Ei
M/muDwyV0KB62lyPzPjxBEno7dmlMr69lHmVPAvArM89vqA2jpB3v8YugLjuQ/Pg
KlS8Rxg8FH00vlrWObdwWIc7p8cQIf5H8QRHCqURdbtkZ4XtG79I7Qk5wauzmZfN
f+s=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_subca_restr_ok = `-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTgwMTI4MjNaFw00MDAzMDUwMTI4MjNaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyG4FreI0nED+bgVY6
piX7DborHXEM77PNpdjLriZIyTYVWCgUmj0F72KRHWbkVtYrxVhy0JjfbJztvWoJ
RoXvvqi7RcEGa2ak0HPIPvV3iePqvsn8PTWC5tyrI46gMsIMJ0vbqjiTE4JgdipN
F/E4S89N5NudvrStA7Gob4z6AeIvmoHr3Gypy87i+in0xiHmIO99T3A1vb+SOwOy
IzTPXRbF4tp07DO3q9u8JpPys1CPlgxs9pnrBA2unXNv0grM98HXW/OulgVO/T2H
NHvkFt6GjhZOTyiFK6ROnmn82iveP2BqPTzZLVi0Pwwk8sC7YMipkc5iQ/u8FT4d
6hvhAgMBAAGjgZ4wgZswgYcGA1UdHgEB/wR9MHugeTBBpD8wPTELMAkGA1UEBhMC
Rk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQwwCgYDVQQLDANP
dVgwNKQyMDAxCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJtaXR0ZWQxDTALBgNV
BAoMBE9yZzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAQC4m
/2AhJb6C2RzWtaOjk9OF+Y6rCgJq6zswwXy17apmNxG2c7ib6TU5SOf2A+IFAhaN
ZxhWXzVqq9H+qOT0HuhKdBcTf4SUncvQ4mlgo3fKZfgcVDZ4NC01/JfD8G768lVT
R1PJQhpR0SqrhUPhMTw7+3Dm0kHIO819t31AwAoFWH+QLOB6/w0bswaTMdOgVHGc
/2d9X4ZJfE5ufyOrf9EFxCQCFCSKOUzpzHxIDRgd2pBvvAS/+KO65tYsHO84Hc3v
cIWtYq48e2jFA7kWzKmosKTlLqwBOYqNQ0A5yrkQRhFzl4i1BwfQ4OMEJ3Rf/JIW
R2b9G1qpy36jqZQzxQ==
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_subca_restr_ok = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxODAxMjgyM1oXDTM5MTEyNjAxMjgyM1owTDELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQwwCgYDVQQLDANPdVgx
DTALBgNVBAMMBExlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDh
w6nC02HVa2rOD/66Nzv7e+JNNePz7WkDUD9sA8Czjgly9gB94XCAmW38tovgAkcx
WQNaYermjaFVefWmicyjJDpdEsjrKbL83c8shp9a7a4LFlVSroZwjO7W8ioclPVH
dsb6OUq2t/l+roKa70TjSJv7ZdZI3//pWlnvhgCCFpXh4eIGxRTRw7xIMaj8Naw5
e5kdeT5hZ1BmLxwhZE0yFMaxVMfCAYqbT/MNmD7a3UFknRkafMfpGU/FXs44F723
jTywu8aattRiq/9NO0+NfrrSP0ALGQBXzsJMsGXFl0JBvNgXysbBGdMuvNwOSCa/
iBHoBXn7wKEWWDdruDHLAgMBAAGjHzAdMBsGA1UdEQQUMBKCEGxlYWYuZXhhbXBs
ZS5jb20wDQYJKoZIhvcNAQENBQADggEBADkGGgwWLTMQ+P7wMMTE32AC940rBHGM
yxckjRKCN0w2O+eu5vx7MjAMKb/dLT+KSKliPeRaU3vLaetXuIsuCnqKkdAW0V8e
hMjPuj1ud40Un5bdRmWhLjr+bok+Grcqb1HwRX82kzqkxY2wQRNrYwplJ2NBsr9W
+yBHxe0mcsKCMOuz52lXBwZ+dmOBzotcxRCQqB2WXPkvHPxVdbywLcT5lyC3DBMB
z6ITKAjZl9Zv/pM720649GpqW4nJJzCvnPGA6nhKmLhbr/QaXq/cwJ5C1IObNVW/
U+IxRmdHsRiGIDgL4rt37u5VA9QucSsfHeboePYjMU4nM4f6g7ixtGQ=
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_subca_restr_fail = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUY49WkHoq+tF4DzsOBI/lYhJjFDgwDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE4MDEyODIzWhcNNDAwNjEzMDEy
ODIzWjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAM5I3sr7WI+CdKd0KpTH8PsIdt+SX0dtl5hoojYtaUdn7HMAwRDZbvVH
jy+/pvehrRN2FTtUngy+4qJaQsnFT1mBlKXhabLnU0vXHfkjVSmCYsC01KNjMeeN
Ilskp4jXkp38HK9tGH8VpWLiaICmhxsqQCeEDGBMKfjTm2WKrK3GbDwQ8ump7fQx
JSSpt5t8H1D01oXjvsZpefWjuhl2u18cNJ1irvmTmRw4aTEI8c5R4cFK+BNmbab6
fkRsvZNmdBQw1Q8G4zXGqrSx2xN7BmY58hZqrAQA+dVxNSitc8dElCZ6D1r/et0v
S8qZ+GbSAB2Fy8aF8dULy1HU2ZHy4tUCAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAMtx9Ky+BRDma0CfMaSE
sN/Dac0F1qZj02FXKrgVRC/ifoKVYOjAuH1RveSjpDMnUYQ6qEnWhiXDuZ87C0a7
KTQuckGZfTo97hozkS6HHSVAwZi3P6G4DoQsqd+BXTYngYON2xGPgigKD71zdZG0
04QJEr3BAyOCft8kIzF3bsP3saxW/IdEQGYSR7WwbuP2XZvg3ZYIgUNpOxZH/Pi0
8MeQjm9PNLFeuzSAKLnioMhO41csEPdkB6ExS0DYfrbswwe16IT1wIPkRaMJRZN8
zGKlqTKP9Ft3jkSD5Q0H1noKAmZceIPUQEBoypCRKS5GYgjli3vPMpfneBSoQjf3
3Y8=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_subca_restr_fail = `-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTgwMTI4MjNaFw00MDAzMDUwMTI4MjNaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsKBQgO6RZ1N//V+59
+xhsPPO57gdzwlb0p4ifA6MNpg2p74XjNSoYm/TTQ2xs4Gyxj0Gp+ml2XUTMp6Oo
x7e9Z6MIJD1j6KFf2kapfH9mi6Tg79sa8pHSTEDKRFyNc8uNTwi4KwrQgT7cJLcp
hB/jfv2BKRVap8x/IkOI+Wk4lruVQhUAeRVEXElYlrQms8E93v/XHBkLbh1v07ah
Syf5gGtJ1YaC9eSkbGLXHCmUw4AlzyK4nH6lOPEfQme5EkhUOtWjsghkvCUmkMl3
yuk52/O1XK6D78eWA2MqjwFZ9oOKlSzSJiB56fpNqT2FYRQdgatBRYLNLLaIDpul
N1EbAgMBAAGjgZ4wgZswgYcGA1UdHgEB/wR9MHugeTBBpD8wPTELMAkGA1UEBhMC
Rk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQwwCgYDVQQLDANP
dVgwNKQyMDAxCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJtaXR0ZWQxDTALBgNV
BAoMBE9yZzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAtS9k
V7Yv/c858v8kBdaGWSd3r14iMOuQznCOE3XTPrS1C0hinvKjWcx5iWIEJtgpJDy6
nX7YtR1RPtdyKkWG9dvY4AtDRN4zEOXdLR3UthDPlLSaZ3QIXUKw61SBtcHJfa+J
HcEC+ICjxxwsCcTFBcY576tE/OcM7e4kqgLkbz6Hzd0l9N5UYWNfQT7e6EbfSDhn
4WmPxIAKsE1Csn95hVymC7NGqFM+GOUu8KW3XCiMMcj091a4x+BA8Ks1+rQqoMyU
T6H2DccsggD+frCgtKgxOStRaVh/mOYGQjbbQyfg7/57bMTE312Q4D737P+6kMsm
7lqOF86/aYqAoBLGIg==
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_subca_restr_fail = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxODAxMjgyM1oXDTM5MTEyNjAxMjgyM1owPjELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQ0wCwYDVQQDDARMZWFm
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyQkri+DYu7Oc9jOp9yTb
enYM7jtJoWOJd41H7ExriVqAwMaPaFvIIzGdoi/iOEp1mRjLLmeypCjvcsmz2G8b
ocsskkHzKrLSvQ6qEY85i0QNz4mnWKrpeYcLVWfdcMkm5I+YC0ex7RoouLULiSb/
+c3CKEwPHkFCXxLOimzIcfirjWmqTxxmeW3IM6Yi/cToptXG8nCUVQ3re0oMWmxp
rt7r8BYbZskA93s2EFMBbQBAzhwBBFxIQwfikhoA5J1khIWndqiLTkW0aizHdzOm
ez4MoLzWApyXV666CYWdsDNXOFHdnp7ok7VF+D+OvXSODd6g8M7YlEuhLuPPlQPS
HQIDAQABox8wHTAbBgNVHREEFDASghBsZWFmLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBDQUAA4IBAQCbMXhx+QLNsYhq/xXo2TzSdlRTW64oYNmgBtPAwqW0qY5cyDnz
/X/LLQFGae2mFFgtO21/uYLs3pbuThJj4kVBSwG7fm9cEib4GLpO9Gf+DJyNel1J
SQL80YYAa8yW9lQThTptFxB98piBwIxIO8sW+P60+zh/QNORXBoDfLXvgwGs7P77
Xv9FXWKOpdUUn2MIdCX25XdTP2W/avztwrAhoo3izC8uhK+mqVEixQGIdKx1o2Vq
v0IJQk/MARF9wXWtkX6UghGSii6OA95pEyv940JHYAZ6uZvvg97pN8pGJfO89m6h
TJExl0p1rxT7TbGrrRClMg9dXSXh6F6uew9U
-----END CERTIFICATE-----`

const dirNameConstraintRootCA_subca_relax_fail = `-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUVJsYgTK/J+ER7U2Qpo20qAokMzswDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCRk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwD
T3JnMQ8wDQYDVQQDDAZSb290Q0EwHhcNMjAwNjE4MDEyODI0WhcNNDAwNjEzMDEy
ODI0WjBAMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQK
DANPcmcxDzANBgNVBAMMBlJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMJDPxG4LHZnM4fK8hSgFxVFplpkwbyqDIoYJPi1GgJ+PCCvjGvFqSQw
FRu0bRXOim5x78kx2/abg7kKVU7P0izBNR3axFsfUPdcSDR8kwAwaC80inmAibMP
z62OrM/rpSykRct1tVFwScYWfX8TT0LlWr21bkO3TekEle3DhW2Aj9eRSG4oOqrs
D8i7cMlLMSTq+2VwRiXXhchax3H7T23O33wKs/8aDFiuhwqHAa6YTFDBkOFmL60Y
i55a8sTV7hgQfnvsuExOIYQKvUu06iBcMywTTpE/ZrX2X53L8U5UoUvXogSNi4Nf
k/vGWhYiYl6Gby2FlC4uw1hOT4hRU18CAwEAAaOBrzCBrDCBlQYDVR0eAQH/BIGK
MIGHoIGEMDOkMTAvMQswCQYDVQQGEwJGTzESMBAGA1UECAwJUGVybWl0dGVkMQww
CgYDVQQKDANPcmcwTaRLMEkxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJ
k/IsZAEZFgdleGFtcGxlMRkwFwYKCZImiZPyLGQBGRYJcGVybWl0dGVkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDQYJKoZIhvcNAQELBQADggEBAFsmKPJMhx7CQ8rhtRO1
sV4ybRu4Ghe2kE3HH84Q9RonZ5oDIAo7xNBWBgiGTjNK3jdtalNsmuErmGHLSPHh
u+nHmJWcyN+ebq9AGXwZ02YHeql0EXbgt7mp6+yYd8kPRr4mtzeWhU/qeR1nXo8W
rxRdtEt7jgeEXiD4vnGQgbCtokn2563RVMRaHW4jL8OuSIQvk8kirUBFi1nTsx33
sGs64n9SFFl8xBFSbt0UPuJKM0twV7b2P1bZgp9NoBO7TaInmk3Kp8+F/x+O3ee+
c5LdSWd1i4gT+71mRmuGLZ0GQ9ZRVS+8tNlMRQ09Sl3pjF4gPWtjRtTGBB5ZWqjR
YKY=
-----END CERTIFICATE-----`
const dirNameConstraintSubCA_subca_relax_fail = `-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDzANBgNVBAMMBlJvb3RD
QTAeFw0yMDA2MTgwMTI4MjRaFw00MDAzMDUwMTI4MjRaMD8xCzAJBgNVBAYTAkZP
MRIwEAYDVQQIDAlQZXJtaXR0ZWQxDDAKBgNVBAoMA09yZzEOMAwGA1UEAwwFU3Vi
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxlKpMxkI/BCGHzinE
JhFp91Me94aNmhLNL5ollDc+S4AYEDhpHGPP5ilqt5+RL906lQtD0bG6qIJ7PiKd
ipya+428BbPDSDJIYQx14NBZ/IU5ZIudH2NGY3J4WW27/wn2v0busWt6ZS1+IYuB
B3mRrDyZjYB2hQlmkAEQdi9+cU5u8T7jb5RAbu6cK0b9zfPGy5lP1MGmowDRgsQE
jIuS6LXK2BXjyd9RatJjv9woCZuQ1qR+YZY5OsQLCm5JFQZZ5/QHezthokaePBAN
0kTHLEm80l1SJKk/x6AuhM2E2xsfqorSu3Vxx81uio9lLkx5PRZrGjEdN2660i0q
wUjpAgMBAAGjgZ4wgZswgYcGA1UdHgEB/wR9MHugeTBBpD8wPTELMAkGA1UEBhMC
Rk8xEjAQBgNVBAgMCVBlcm1pdHRlZDEMMAoGA1UECgwDT3JnMQwwCgYDVQQLDANP
dVgwNKQyMDAxCzAJBgNVBAYTAkZPMRIwEAYDVQQIDAlQZXJtaXR0ZWQxDTALBgNV
BAoMBE9yZzIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAjrsR
rdwDO99BnpAIWseZR1B+W7QX4PrM9Eoh9G9YuUVzILXTBAoq2X0YSXp1+etkWMd8
3Al9PiGoEfhCIPToczfAmgQtIJowfFI0wnwB5GLce1wDQEgihRkM9ful4DZQ+gdW
ToJrJD2v7gMJAX8Y3ByOm3NKoHzlyiyVgo7pJhNjIZStpqbRXKw8rS9FXAM5M6zG
ht+e6bmFTKuRTxyK1W51r0vdsV6O0R+1VH8mj5XXFmTZ9EU0ExNjXl3LOU+mjrKM
uxjzuJT6t2dGwOYEzZH3mVV/CfpIlXDbmVSsJRkh0s+ssXY3ZFN4o1yBYWx9Z/Nq
PN0V1hB67ZfEK3OOyA==
-----END CERTIFICATE-----`
const dirNameConstraintLeafCA_subca_relax_fail = `-----BEGIN CERTIFICATE-----
MIIDGDCCAgCgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA/MQswCQYDVQQGEwJGTzES
MBAGA1UECAwJUGVybWl0dGVkMQwwCgYDVQQKDANPcmcxDjAMBgNVBAMMBVN1YkNB
MB4XDTIwMDYxODAxMjgyNFoXDTM5MTEyNjAxMjgyNFowPzELMAkGA1UEBhMCRk8x
EjAQBgNVBAgMCVBlcm1pdHRlZDENMAsGA1UECgwET3JnMjENMAsGA1UEAwwETGVh
ZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM+0S7NZaxtLZIrg6s8N
a2JzHBYHizdqlaL0oowf6Er7c483/VzYwKJ2AB61R3Sxr3/6SQSmyjiXZW5rVWJp
WJH5MKka+LKi/fWvDWPHFc4bM0xGZ7F0wowewvvnbOGmRr9HFTqXs6O4p1MWe5Qy
5jah/HEHaRCP1QMxa2GVgMdNijMDdmvicF149yB7FY1mqbBXA0OED8fTvW/oP4ns
aX5HiY38sM0gXtx2t+HiThIB5utVhefAnNCKFmjLIpiMpAxa+JQcgdVz2PkLBAVk
473idSFVsbTL0A0Ney1kyoCI0yU7eK/I5TgCBbNnGMbJy7xdzwexepzrJQGd3PQi
6KUCAwEAAaMfMB0wGwYDVR0RBBQwEoIQbGVhZi5leGFtcGxlLmNvbTANBgkqhkiG
9w0BAQ0FAAOCAQEATYyFhjlHa+EdWdVyE4hRYEJUeoSL1CLWSNsnRqlSRUj6f47B
Z6ppHFCIaOKS1HWTRmxlR8ZZacGesdrISec21CJkfMjQe8ha4Og9mwTxYBvfkAz0
n7czYC97N7b4+wTwwGREclO4QphcgUwW1FOU5yPHAGLmKNvJpXEKN+TDya08Gmam
OQMzV3zvbJlDICnYjwgIbdlTjDvdOhGmiSF/MU5F2FXXN9kotcRQdJQL6lPIB84/
ixyGmqlNXtjKU9ADJIrNIFajvXTl4ln2Jrfu42hKCpDsvT07GLYSTfinHQjeTiUR
G1IZnzmYGDbyUgD74HsLWxQoS2zIEuwb/R2mKQ==
-----END CERTIFICATE-----`

var globalSignRoot = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----`

var moipLeafCert = `-----BEGIN CERTIFICATE-----
MIIGQDCCBSigAwIBAgIRAPe/cwh7CUWizo8mYSDavLIwDQYJKoZIhvcNAQELBQAw
gZIxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTgwNgYD
VQQDEy9DT01PRE8gUlNBIEV4dGVuZGVkIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZl
ciBDQTAeFw0xMzA4MTUwMDAwMDBaFw0xNDA4MTUyMzU5NTlaMIIBQjEXMBUGA1UE
BRMOMDg3MTg0MzEwMDAxMDgxEzARBgsrBgEEAYI3PAIBAxMCQlIxGjAYBgsrBgEE
AYI3PAIBAhMJU2FvIFBhdWxvMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlv
bjELMAkGA1UEBhMCQlIxETAPBgNVBBETCDAxNDUyMDAwMRIwEAYDVQQIEwlTYW8g
UGF1bG8xEjAQBgNVBAcTCVNhbyBQYXVsbzEtMCsGA1UECRMkQXZlbmlkYSBCcmln
YWRlaXJvIEZhcmlhIExpbWEgLCAyOTI3MR0wGwYDVQQKExRNb2lwIFBhZ2FtZW50
b3MgUy5BLjENMAsGA1UECxMETU9JUDEYMBYGA1UECxMPU1NMIEJsaW5kYWRvIEVW
MRgwFgYDVQQDEw9hcGkubW9pcC5jb20uYnIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDN0b9x6TrXXA9hPCF8/NjqGJ++2D4LO4ZiMFTjs0VwpXy2Y1Oe
s74/HuiLGnAHxTmAtV7IpZMibiOcTxcnDYp9oEWkf+gR+hZvwFZwyOBC7wyb3SR3
UvV0N1ZbEVRYpN9kuX/3vjDghjDmzzBwu8a/T+y5JTym5uiJlngVAWyh/RjtIvYi
+NVkQMbyVlPGkoCe6c30pH8DKYuUCZU6DHjUsPTX3jAskqbhDSAnclX9iX0p2bmw
KVBc+5Vh/2geyzDuquF0w+mNIYdU5h7uXvlmJnf3d2Cext5dxdL8/jezD3U0dAqI
pYSKERbyxSkJWxdvRlhdpM9YXMJcpc88xNp1AgMBAAGjggHcMIIB2DAfBgNVHSME
GDAWgBQ52v/KKBSKqHQTCLnkDqnS+n6daTAdBgNVHQ4EFgQU/lXuOa7DMExzZjRj
LQWcMWGZY7swDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMEYGA1UdIAQ/MD0wOwYMKwYBBAGyMQECAQUB
MCswKQYIKwYBBQUHAgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5jb20vQ1BTMFYG
A1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NPTU9ET1JT
QUV4dGVuZGVkVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNybDCBhwYIKwYBBQUH
AQEEezB5MFEGCCsGAQUFBzAChkVodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01P
RE9SU0FFeHRlbmRlZFZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAvBgNVHREEKDAmgg9hcGku
bW9pcC5jb20uYnKCE3d3dy5hcGkubW9pcC5jb20uYnIwDQYJKoZIhvcNAQELBQAD
ggEBAFoTmPlaDcf+nudhjXHwud8g7/LRyA8ucb+3/vfmgbn7FUc1eprF5sJS1mA+
pbiTyXw4IxcJq2KUj0Nw3IPOe9k84mzh+XMmdCKH+QK3NWkE9Udz+VpBOBc0dlqC
1RH5umStYDmuZg/8/r652eeQ5kUDcJyADfpKWBgDPYaGtwzKVT4h3Aok9SLXRHx6
z/gOaMjEDMarMCMw4VUIG1pvNraZrG5oTaALPaIXXpd8VqbQYPudYJ6fR5eY3FeW
H/ofbYFdRcuD26MfBFWE9VGGral9Fgo8sEHffho+UWhgApuQV4/l5fMzxB5YBXyQ
jhuy8PqqZS9OuLilTeLu4a8z2JI=
-----END CERTIFICATE-----`

var comodoIntermediateSHA384 = `-----BEGIN CERTIFICATE-----
MIIGDjCCA/agAwIBAgIQBqdDgNTr/tQ1taP34Wq92DANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTIwMjEy
MDAwMDAwWhcNMjcwMjExMjM1OTU5WjCBkjELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxODA2BgNVBAMTL0NPTU9ETyBSU0EgRXh0ZW5kZWQg
VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAlVbeVLTf1QJJe9FbXKKyHo+cK2JMK40SKPMalaPGEP0p3uGf
CzhAk9HvbpUQ/OGQF3cs7nU+e2PsYZJuTzurgElr3wDqAwB/L3XVKC/sVmePgIOj
vdwDmZOLlJFWW6G4ajo/Br0OksxgnP214J9mMF/b5pTwlWqvyIqvgNnmiDkBfBzA
xSr3e5Wg8narbZtyOTDr0VdVAZ1YEZ18bYSPSeidCfw8/QpKdhQhXBZzQCMZdMO6
WAqmli7eNuWf0MLw4eDBYuPCGEUZUaoXHugjddTI0JYT/8ck0YwLJ66eetw6YWNg
iJctXQUL5Tvrrs46R3N2qPos3cCHF+msMJn4HwIDAQABo4IBaTCCAWUwHwYDVR0j
BBgwFoAUu69+Aj36pvE8hI6t7jiY7NkyMtQwHQYDVR0OBBYEFDna/8ooFIqodBMI
ueQOqdL6fp1pMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMD4G
A1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5j
b21vZG8uY29tL0NQUzBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9k
b2NhLmNvbS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggr
BgEFBQcBAQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29t
L0NPTU9ET1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
cC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAERCnUFRK0iIXZebeV4R
AUpSGXtBLMeJPNBy3IX6WK/VJeQT+FhlZ58N/1eLqYVeyqZLsKeyLeCMIs37/3mk
jCuN/gI9JN6pXV/kD0fQ22YlPodHDK4ixVAihNftSlka9pOlk7DgG4HyVsTIEFPk
1Hax0VtpS3ey4E/EhOfUoFDuPPpE/NBXueEoU/1Tzdy5H3pAvTA/2GzS8+cHnx8i
teoiccsq8FZ8/qyo0QYPFBRSTP5kKwxpKrgNUG4+BAe/eiCL+O5lCeHHSQgyPQ0o
fkkdt0rvAucNgBfIXOBhYsvss2B5JdoaZXOcOBCgJjqwyBZ9kzEi7nQLiMBciUEA
KKlHMd99SUWa9eanRRrSjhMQ34Ovmw2tfn6dNVA0BM7pINae253UqNpktNEvWS5e
ojZh1CSggjMziqHRbO9haKPl0latxf1eYusVqHQSTC8xjOnB3xBLAer2VBvNfzu9
XJ/B288ByvK6YBIhMe2pZLiySVgXbVrXzYxtvp5/4gJYp9vDLVj2dAZqmvZh+fYA
tmnYOosxWd2R5nwnI4fdAw+PKowegwFOAWEMUnNt/AiiuSpm5HZNMaBWm9lTjaK2
jwLI5jqmBNFI+8NKAnb9L9K8E7bobTQk+p0pisehKxTxlgBzuRPpwLk6R1YCcYAn
pLwltum95OmYdBbxN4SBB7SC
-----END CERTIFICATE-----`

const comodoRSAAuthority = `-----BEGIN CERTIFICATE-----
MIIFdDCCBFygAwIBAgIQJ2buVutJ846r13Ci/ITeIjANBgkqhkiG9w0BAQwFADBv
MQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFk
ZFRydXN0IEV4dGVybmFsIFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBF
eHRlcm5hbCBDQSBSb290MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFow
gYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD
VQQDEyJDT01PRE8gUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkehUktIKVrGsDSTdxc9EZ3SZKzejfSNw
AHG8U9/E+ioSj0t/EFa9n3Byt2F/yUsPF6c947AEYe7/EZfH9IY+Cvo+XPmT5jR6
2RRr55yzhaCCenavcZDX7P0N+pxs+t+wgvQUfvm+xKYvT3+Zf7X8Z0NyvQwA1onr
ayzT7Y+YHBSrfuXjbvzYqOSSJNpDa2K4Vf3qwbxstovzDo2a5JtsaZn4eEgwRdWt
4Q08RWD8MpZRJ7xnw8outmvqRsfHIKCxH2XeSAi6pE6p8oNGN4Tr6MyBSENnTnIq
m1y9TBsoilwie7SrmNnu4FGDwwlGTm0+mfqVF9p8M1dBPI1R7Qu2XK8sYxrfV8g/
vOldxJuvRZnio1oktLqpVj3Pb6r/SVi+8Kj/9Lit6Tf7urj0Czr56ENCHonYhMsT
8dm74YlguIwoVqwUHZwK53Hrzw7dPamWoUi9PPevtQ0iTMARgexWO/bTouJbt7IE
IlKVgJNp6I5MZfGRAy1wdALqi2cVKWlSArvX31BqVUa/oKMoYX9w0MOiqiwhqkfO
KJwGRXa/ghgntNWutMtQ5mv0TIZxMOmm3xaG4Nj/QN370EKIf6MzOi5cHkERgWPO
GHFrK+ymircxXDpqR+DDeVnWIBqv8mqYqnK8V0rSS527EPywTEHl7R09XiidnMy/
s1Hap0flhFMCAwEAAaOB9DCB8TAfBgNVHSMEGDAWgBStvZh6NLQm9/rEJlTvA73g
JMtUGjAdBgNVHQ4EFgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQD
AgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRVHSAAMEQGA1UdHwQ9
MDswOaA3oDWGM2h0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9BZGRUcnVzdEV4dGVy
bmFsQ0FSb290LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6
Ly9vY3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggEBAGS/g/FfmoXQ
zbihKVcN6Fr30ek+8nYEbvFScLsePP9NDXRqzIGCJdPDoCpdTPW6i6FtxFQJdcfj
Jw5dhHk3QBN39bSsHNA7qxcS1u80GH4r6XnTq1dFDK8o+tDb5VCViLvfhVdpfZLY
Uspzgb8c8+a4bmYRBbMelC1/kZWSWfFMzqORcUx8Rww7Cxn2obFshj5cqsQugsv5
B5a6SE2Q8pTIqXOi6wZ7I53eovNNVZ96YUWYGGjHXkBrI/V5eu+MtWuLt29G9Hvx
PUsE2JOAWVrgQSQdso8VYFhH2+9uRv0V9dlfmrPb2LjkQLPNlzmuhbsdjrzch5vR
pu/xO28QOG8=
-----END CERTIFICATE-----`

const addTrustRoot = `-----BEGIN CERTIFICATE-----
MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU
MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs
IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290
MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux
FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h
bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt
H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9
uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX
mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX
a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN
E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0
WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD
VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0
Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU
cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN
AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH
YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5
6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC
Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX
c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a
mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=
-----END CERTIFICATE-----`

const selfSigned = `-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIRAK0SWRVmi67xU3z0gkgY+PkwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTkxNjMzNDdaFw0xNzA4MTkxNjMz
NDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDWkm1kdCwxyKEt6OTmZitkmLGH8cQu9z7rUdrhW8lWNm4kh2SuaUWP
pscBjda5iqg51aoKuWJR2rw6ElDne+X5eit2FT8zJgAU8v39lMFjbaVZfS9TFOYF
w0Tk0Luo/PyKJpZnwhsP++iiGQiteJbndy8aLKmJ2MpLfpDGIgxEIyNb5dgoDi0D
WReDCpE6K9WDYqvKVGnQ2Jvqqra6Gfx0tFkuqJxQuqA8aUOlPHcCH4KBZdNEoXdY
YL3E4dCAh0YiDs80wNZx4cHqEM3L8gTEFqW2Tn1TSuPZO6gjJ9QPsuUZVjaMZuuO
NVxqLGujZkDzARhC3fBpptMuaAfi20+BAgMBAAGjTTBLMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBYGA1UdEQQPMA2C
C2Zvby5leGFtcGxlMA0GCSqGSIb3DQEBCwUAA4IBAQBPvvfnDhsHWt+/cfwdAVim
4EDn+hYOMkTQwU0pouYIvY8QXYkZ8MBxpBtBMK4JhFU+ewSWoBAEH2dCCvx/BDxN
UGTSJHMbsvJHcFvdmsvvRxOqQ/cJz7behx0cfoeHMwcs0/vWv8ms5wHesb5Ek7L0
pl01FCBGTcncVqr6RK1r4fTpeCCfRIERD+YRJz8TtPH6ydesfLL8jIV40H8NiDfG
vRAvOtNiKtPzFeQVdbRPOskC4rcHyPeiDAMAMixeLi63+CFty4da3r5lRezeedCE
cw3ESZzThBwWqvPOtJdpXdm+r57pDW8qD+/0lY8wfImMNkQAyCUCLg/1Lxt/hrBj
-----END CERTIFICATE-----`

const issuerSubjectMatchRoot = `-----BEGIN CERTIFICATE-----
MIICIDCCAYmgAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwIzEPMA0GA1UE
ChMGR29sYW5nMRAwDgYDVQQDEwdSb290IGNhMB4XDTE1MDEwMTAwMDAwMFoXDTI1
MDEwMTAwMDAwMFowIzEPMA0GA1UEChMGR29sYW5nMRAwDgYDVQQDEwdSb290IGNh
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpDn8RDOZa5oaDcPZRBy4CeBH1
siSSOO4mYgLHlPE+oXdqwI/VImi2XeJM2uCFETXCknJJjYG0iJdrt/yyRFvZTQZw
+QzGj+mz36NqhGxDWb6dstB2m8PX+plZw7jl81MDvUnWs8yiQ/6twgu5AbhWKZQD
JKcNKCEpqa6UW0r5nwIDAQABo10wWzAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIE
EEA31wH7QC+4HH5UBCeMWQEwDQYJKoZIhvcNAQELBQADgYEAb4TfSeCZ1HFmHTKG
VsvqWmsOAGrRWm4fBiMH/8vRGnTkJEMLqiqgc3Ulgry/P6n4SIis7TqUOw3TiMhn
RGEz33Fsxa/tFoy/gvlJu+MqB1M2NyV33pGkdwl/b7KRWMQFieqO+uE7Ge/49pS3
eyfm5ITdK/WT9TzYhsU4AVZcn20=
-----END CERTIFICATE-----`

const issuerSubjectMatchLeaf = `-----BEGIN CERTIFICATE-----
MIICODCCAaGgAwIBAgIJAOjwnT/iW+qmMA0GCSqGSIb3DQEBCwUAMCMxDzANBgNV
BAoTBkdvbGFuZzEQMA4GA1UEAxMHUm9vdCBDQTAeFw0xNTAxMDEwMDAwMDBaFw0y
NTAxMDEwMDAwMDBaMCAxDzANBgNVBAoTBkdvbGFuZzENMAsGA1UEAxMETGVhZjCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA20Z9ky4SJwZIvAYoIat+xLaiXf4e
UkWIejZHpQgNkkJbwoHAvpd5mED7T20U/SsTi8KlLmfY1Ame1iI4t0oLdHMrwjTx
0ZPlltl0e/NYn2xhPMCwQdTZKyskI3dbHDu9dV3OIFTPoWOHHR4kxPMdGlCLqrYU
Q+2Xp3Vi9BTIUtcCAwEAAaN3MHUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMBkGA1UdDgQSBBCfkRYf
Q0M+SabebbaA159gMBsGA1UdIwQUMBKAEEA31wH7QC+4HH5UBCeMWQEwDQYJKoZI
hvcNAQELBQADgYEAjYYF2on1HcUWFEG5NIcrXDiZ49laW3pb3gtcCEUJbxydMV8I
ynqjmdqDCyK+TwI1kU5dXDe/iSJYfTB20i/QoO53nnfA1hnr7KBjNWqAm4AagN5k
vEA4PCJprUYmoj3q9MKSSRYDlq5kIbl87mSRR4GqtAwJKxIasvOvULOxziQ=
-----END CERTIFICATE-----`

const x509v1TestRoot = `-----BEGIN CERTIFICATE-----
MIICIDCCAYmgAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwIzEPMA0GA1UE
ChMGR29sYW5nMRAwDgYDVQQDEwdSb290IENBMB4XDTE1MDEwMTAwMDAwMFoXDTI1
MDEwMTAwMDAwMFowIzEPMA0GA1UEChMGR29sYW5nMRAwDgYDVQQDEwdSb290IENB
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpDn8RDOZa5oaDcPZRBy4CeBH1
siSSOO4mYgLHlPE+oXdqwI/VImi2XeJM2uCFETXCknJJjYG0iJdrt/yyRFvZTQZw
+QzGj+mz36NqhGxDWb6dstB2m8PX+plZw7jl81MDvUnWs8yiQ/6twgu5AbhWKZQD
JKcNKCEpqa6UW0r5nwIDAQABo10wWzAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIE
EEA31wH7QC+4HH5UBCeMWQEwDQYJKoZIhvcNAQELBQADgYEAcIwqeNUpQr9cOcYm
YjpGpYkQ6b248xijCK7zI+lOeWN89zfSXn1AvfsC9pSdTMeDklWktbF/Ad0IN8Md
h2NtN34ard0hEfHc8qW8mkXdsysVmq6cPvFYaHz+dBtkHuHDoy8YQnC0zdN/WyYB
/1JmacUUofl+HusHuLkDxmadogI=
-----END CERTIFICATE-----`

const x509v1TestIntermediate = `-----BEGIN CERTIFICATE-----
MIIByjCCATMCCQCCdEMsT8ykqTANBgkqhkiG9w0BAQsFADAjMQ8wDQYDVQQKEwZH
b2xhbmcxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcNMTUwMTAxMDAwMDAwWhcNMjUwMTAx
MDAwMDAwWjAwMQ8wDQYDVQQKEwZHb2xhbmcxHTAbBgNVBAMTFFguNTA5djEgaW50
ZXJtZWRpYXRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ2QyniAOT+5YL
jeinEBJr3NsC/Q2QJ/VKmgvp+xRxuKTHJiVmxVijmp0vWg8AWfkmuE4p3hXQbbqM
k5yxrk1n60ONhim2L4VXriEvCE7X2OXhTmBls5Ufr7aqIgPMikwjScCXwz8E8qI8
UxyAhnjeJwMYBU8TuwBImSd4LBHoQQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAIab
DRG6FbF9kL9jb/TDHkbVBk+sl/Pxi4/XjuFyIALlARgAkeZcPmL5tNW1ImHkwsHR
zWE77kJDibzd141u21ZbLsKvEdUJXjla43bdyMmEqf5VGpC3D4sFt3QVH7lGeRur
x5Wlq1u3YDL/j6s1nU2dQ3ySB/oP7J+vQ9V4QeM+
-----END CERTIFICATE-----`

const x509v1TestLeaf = `-----BEGIN CERTIFICATE-----
MIICMzCCAZygAwIBAgIJAPo99mqJJrpJMA0GCSqGSIb3DQEBCwUAMDAxDzANBgNV
BAoTBkdvbGFuZzEdMBsGA1UEAxMUWC41MDl2MSBpbnRlcm1lZGlhdGUwHhcNMTUw
MTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjArMQ8wDQYDVQQKEwZHb2xhbmcxGDAW
BgNVBAMTD2Zvby5leGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEApUh60Z+a5/oKJxG//Dn8CihSo2CJHNIIO3zEJZ1EeNSMZCynaIR6D3IPZEIR
+RG2oGt+f5EEukAPYxwasp6VeZEezoQWJ+97nPCT6DpwLlWp3i2MF8piK2R9vxkG
Z5n0+HzYk1VM8epIrZFUXSMGTX8w1y041PX/yYLxbdEifdcCAwEAAaNaMFgwDgYD
VR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNV
HRMBAf8EAjAAMBkGA1UdDgQSBBBFozXe0SnzAmjy+1U6M/cvMA0GCSqGSIb3DQEB
CwUAA4GBADYzYUvaToO/ucBskPdqXV16AaakIhhSENswYVSl97/sODaxsjishKq9
5R7siu+JnIFotA7IbBe633p75xEnLN88X626N/XRFG9iScLzpj0o0PWXBUiB+fxL
/jt8qszOXCv2vYdUTPNuPqufXLWMoirpuXrr1liJDmedCcAHepY/
-----END CERTIFICATE-----`

const ignoreCNWithSANRoot = `-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIIJkzCwkNrPHMwDQYJKoZIhvcNAQELBQAwMDEQMA4GA1UE
ChMHVEVTVElORzEcMBoGA1UEAxMTKipUZXN0aW5nKiogUm9vdCBDQTAeFw0xNTAx
MDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMDAxEDAOBgNVBAoTB1RFU1RJTkcxHDAa
BgNVBAMTEyoqVGVzdGluZyoqIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC4YAf5YqlXGcikvbMWtVrNICt+V/NNWljwfvSKdg4Inm7k6BwW
P6y4Y+n4qSYIWNU4iRkdpajufzctxQCO6ty13iw3qVktzcC5XBIiS6ymiRhhDgnY
VQqyakVGw9MxrPwdRZVlssUv3Hmy6tU+v5Ok31SLY5z3wKgYWvSyYs0b8bKNU8kf
2FmSHnBN16lxGdjhe3ji58F/zFMr0ds+HakrLIvVdFcQFAnQopM8FTHpoWNNzGU3
KaiO0jBbMFkd6uVjVnuRJ+xjuiqi/NWwiwQA+CEr9HKzGkxOF8nAsHamdmO1wW+w
OsCrC0qWQ/f5NTOVATTJe0vj88OMTvo3071VAgMBAAGjXTBbMA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUw
AwEB/zAZBgNVHQ4EEgQQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOC
AQEAGOn3XjxHyHbXLKrRmpwV447B7iNBXR5VlhwOgt1kWaHDL2+8f/9/h0HMkB6j
fC+/yyuYVqYuOeavqMGVrh33D2ODuTQcFlOx5lXukP46j3j+Lm0jjZ1qNX7vlP8I
VlUXERhbelkw8O4oikakwIY9GE8syuSgYf+VeBW/lvuAZQrdnPfabxe05Tre6RXy
nJHMB1q07YHpbwIkcV/lfCE9pig2nPXTLwYZz9cl46Ul5RCpPUi+IKURo3x8y0FU
aSLjI/Ya0zwUARMmyZ3RRGCyhIarPb20mKSaMf1/Nb23pS3k1QgmZhk5pAnXYsWu
BJ6bvwEAasFiLGP6Zbdmxb2hIA==
-----END CERTIFICATE-----`

const ignoreCNWithSANLeaf = `-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIJAONakvRTxgJhMA0GCSqGSIb3DQEBCwUAMDAxEDAOBgNV
BAoTB1RFU1RJTkcxHDAaBgNVBAMTEyoqVGVzdGluZyoqIFJvb3QgQ0EwHhcNMTUw
MTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAsMRAwDgYDVQQKEwdURVNUSU5HMRgw
FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDBqskp89V/JMIBBqcauKSOVLcMyIE/t0jgSWVrsI4sksBTabLsfMdS
ui2n+dHQ1dRBuw3o4g4fPrWwS3nMnV3pZUHEn2TPi5N1xkjTaxObXgKIY2GKmFP3
rJ9vYqHT6mT4K93kCHoRcmJWWySc7S3JAOhTcdB4G+tIdQJN63E+XRYQQfNrn5HZ
hxQoOzaguHFx+ZGSD4Ntk6BSZz5NfjqCYqYxe+iCpTpEEYhIpi8joSPSmkTMTxBW
S1W2gXbYNQ9KjNkGM6FnQsUJrSPMrWs4v3UB/U88N5LkZeF41SqD9ySFGwbGajFV
nyzj12+4K4D8BLhlOc0Eo/F/8GwOwvmxAgMBAAGjgYkwgYYwDgYDVR0PAQH/BAQD
AgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA
MBkGA1UdDgQSBBCjeab27q+5pV43jBGANOJ1MBsGA1UdIwQUMBKAEEA31wH7QC+4
HH5UBCeMWQEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAGZfZ
ErTVxxpIg64s22mQpXSk/72THVQsfsKHzlXmztM0CJzH8ccoN67ZqKxJCfdiE/FI
Emb6BVV4cGPeIKpcxaM2dwX/Y+Y0JaxpQJvqLxs+EByRL0gPP3shgg86WWCjYLxv
AgOn862d/JXGDrC9vIlQ/DDQcyL5g0JV5UjG2G9TUigbnrXxBw7BoWK6wmoSaHnR
sZKEHSs3RUJvm7qqpA9Yfzm9jg+i9j32zh1xFacghAOmFRFXa9eCVeigZ/KK2mEY
j2kBQyvnyKsXHLAKUoUOpd6t/1PHrfXnGj+HmzZNloJ/BZ1kiWb4eLvMljoLGkZn
xZbqP3Krgjj4XNaXjg==
-----END CERTIFICATE-----`

const excludedNamesLeaf = `-----BEGIN CERTIFICATE-----
MIID4DCCAsigAwIBAgIHDUSFtJknhzANBgkqhkiG9w0BAQsFADCBnjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCUxvcyBHYXRvczEU
MBIGA1UECgwLTmV0ZmxpeCBJbmMxLTArBgNVBAsMJFBsYXRmb3JtIFNlY3VyaXR5
ICgzNzM0NTE1NTYyODA2Mzk3KTEhMB8GA1UEAwwYSW50ZXJtZWRpYXRlIENBIGZv
ciAzMzkyMB4XDTE3MDIwODIxMTUwNFoXDTE4MDIwODIwMjQ1OFowgZAxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlMb3MgR2F0b3Mx
FDASBgNVBAoMC05ldGZsaXggSW5jMS0wKwYDVQQLDCRQbGF0Zm9ybSBTZWN1cml0
eSAoMzczNDUxNTc0ODUwMjY5NikxEzARBgNVBAMMCjE3Mi4xNi4wLjEwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZ0oP1bMv6bOeqcKbzinnGpNOpenhA
zdFFsgea62znWsH3Wg4+1Md8uPCqlaQIsaJQKZHc50eKD3bg0Io7c6kxHkBQr1b8
Q7cGeK3CjdqG3NwS/aizzrLKOwL693hFwwy7JY7GGCvogbhyQRKn6iV0U9zMm7bu
/9pQVV/wx8u01u2uAlLttjyQ5LJkxo5t8cATFVqxdN5J9eY//VSDiTwXnlpQITBP
/Ow+zYuZ3kFlzH3CtCOhOEvNG3Ar1NvP3Icq35PlHV+Eki4otnKfixwByoiGpqCB
UEIY04VrZJjwBxk08y/3jY2B3VLYGgi+rryyCxIqkB7UpSNPMMWSG4UpAgMBAAGj
LzAtMAwGA1UdEwEB/wQCMAAwHQYDVR0RBBYwFIIMYmVuZGVyLmxvY2FshwSsEAAB
MA0GCSqGSIb3DQEBCwUAA4IBAQCLW3JO8L7LKByjzj2RciPjCGH5XF87Wd20gYLq
sNKcFwCIeyZhnQy5aZ164a5G9AIk2HLvH6HevBFPhA9Ivmyv/wYEfnPd1VcFkpgP
hDt8MCFJ8eSjCyKdtZh1MPMLrLVymmJV+Rc9JUUYM9TIeERkpl0rskcO1YGewkYt
qKlWE+0S16+pzsWvKn831uylqwIb8ANBPsCX4aM4muFBHavSWAHgRO+P+yXVw8Q+
VQDnMHUe5PbZd1/+1KKVs1K/CkBCtoHNHp1d/JT+2zUQJphwja9CcgfFdVhSnHL4
oEEOFtqVMIuQfR2isi08qW/JGOHc4sFoLYB8hvdaxKWSE19A
-----END CERTIFICATE-----`

const excludedNamesIntermediate = `-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIHDUSFqYeczDANBgkqhkiG9w0BAQsFADCBmTELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCUxvcyBHYXRvczEU
MBIGA1UECgwLTmV0ZmxpeCBJbmMxLTArBgNVBAsMJFBsYXRmb3JtIFNlY3VyaXR5
ICgzNzM0NTE1NDc5MDY0NjAyKTEcMBoGA1UEAwwTTG9jYWwgUm9vdCBmb3IgMzM5
MjAeFw0xNzAyMDgyMTE1MDRaFw0xODAyMDgyMDI0NThaMIGeMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9zMRQwEgYD
VQQKDAtOZXRmbGl4IEluYzEtMCsGA1UECwwkUGxhdGZvcm0gU2VjdXJpdHkgKDM3
MzQ1MTU1NjI4MDYzOTcpMSEwHwYDVQQDDBhJbnRlcm1lZGlhdGUgQ0EgZm9yIDMz
OTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCOyEs6tJ/t9emQTvlx
3FS7uJSou5rKkuqVxZdIuYQ+B2ZviBYUnMRT9bXDB0nsVdKZdp0hdchdiwNXDG/I
CiWu48jkcv/BdynVyayOT+0pOJSYLaPYpzBx1Pb9M5651ct9GSbj6Tz0ChVonoIE
1AIZ0kkebucZRRFHd0xbAKVRKyUzPN6HJ7WfgyauUp7RmlC35wTmrmARrFohQLlL
7oICy+hIQePMy9x1LSFTbPxZ5AUUXVC3eUACU3vLClF/Xs8XGHebZpUXCdMQjOGS
nq1eFguFHR1poSB8uSmmLqm4vqUH9CDhEgiBAC8yekJ8//kZQ7lUEqZj3YxVbk+Y
E4H5AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
ADxrnmNX5gWChgX9K5fYwhFDj5ofxZXAKVQk+WjmkwMcmCx3dtWSm++Wdksj/ZlA
V1cLW3ohWv1/OAZuOlw7sLf98aJpX+UUmIYYQxDubq+4/q7VA7HzEf2k/i/oN1NI
JgtrhpPcZ/LMO6k7DYx0qlfYq8pTSfd6MI4LnWKgLc+JSPJJjmvspgio2ZFcnYr7
A264BwLo6v1Mos1o1JUvFFcp4GANlw0XFiWh7JXYRl8WmS5DoouUC+aNJ3lmyF6z
LbIjZCSfgZnk/LK1KU1j91FI2bc2ULYZvAC1PAg8/zvIgxn6YM2Q7ZsdEgWw0FpS
zMBX1/lk4wkFckeUIlkD55Y=
-----END CERTIFICATE-----`

const excludedNamesRoot = `-----BEGIN CERTIFICATE-----
MIIEGTCCAwGgAwIBAgIHDUSFpInn/zANBgkqhkiG9w0BAQsFADCBozELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCUxvcyBHYXRvczEU
MBIGA1UECgwLTmV0ZmxpeCBJbmMxLTArBgNVBAsMJFBsYXRmb3JtIFNlY3VyaXR5
ICgzNzMxNTA5NDM3NDYyNDg1KTEmMCQGA1UEAwwdTmFtZSBDb25zdHJhaW50cyBU
ZXN0IFJvb3QgQ0EwHhcNMTcwMjA4MjExNTA0WhcNMTgwMjA4MjAyNDU4WjCBmTEL
MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCUxvcyBH
YXRvczEUMBIGA1UECgwLTmV0ZmxpeCBJbmMxLTArBgNVBAsMJFBsYXRmb3JtIFNl
Y3VyaXR5ICgzNzM0NTE1NDc5MDY0NjAyKTEcMBoGA1UEAwwTTG9jYWwgUm9vdCBm
b3IgMzM5MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJymcnX29ekc
7+MLyr8QuAzoHWznmGdDd2sITwWRjM89/21cdlHCGKSpULUNdFp9HDLWvYECtxt+
8TuzKiQz7qAerzGUT1zI5McIjHy0e/i4xIkfiBiNeTCuB/N9QRbZlcfM80ErkaA4
gCAFK8qZAcWkHIl6e+KaQFMPLKk9kckgAnVDHEJe8oLNCogCJ15558b65g05p9eb
5Lg+E98hoPRTQaDwlz3CZPfTTA2EiEZInSi8qzodFCbTpJUVTbiVUH/JtVjlibbb
smdcx5PORK+8ZJkhLEh54AjaWOX4tB/7Tkk8stg2VBmrIARt/j4UVj7cTrIWU3bV
m8TwHJG+YgsCAwEAAaNaMFgwDwYDVR0TAQH/BAUwAwEB/zBFBgNVHR4EPjA8oBww
CocICgEAAP//AAAwDoIMYmVuZGVyLmxvY2FsoRwwCocICgEAAP//AAAwDoIMYmVu
ZGVyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQAMjbheffPxtSKSv9NySW+8qmHs
n7Mb5GGyCFu+cMZSoSaabstbml+zHEFJvWz6/1E95K4F8jKhAcu/CwDf4IZrSD2+
Hee0DolVSQhZpnHgPyj7ZATz48e3aJaQPUlhCEOh0wwF4Y0N4FV0t7R6woLylYRZ
yU1yRHUqUYpN0DWFpsPbBqgM6uUAVO2ayBFhPgWUaqkmSbZ/Nq7isGvknaTmcIwT
6mOAFN0qFb4RGzfGJW7x6z7KCULS7qVDp6fU3tRoScHFEgRubks6jzQ1W5ooSm4o
+NQCZDd5eFeU8PpNX7rgaYE4GPq+EEmLVCBYmdctr8QVdqJ//8Xu3+1phjDy
-----END CERTIFICATE-----`

const invalidCNRoot = `-----BEGIN CERTIFICATE-----
MIIBFjCBvgIJAIsu4r+jb70UMAoGCCqGSM49BAMCMBQxEjAQBgNVBAsMCVRlc3Qg
cm9vdDAeFw0xODA3MTExODMyMzVaFw0yODA3MDgxODMyMzVaMBQxEjAQBgNVBAsM
CVRlc3Qgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF6oDgMg0LV6YhPj
QXaPXYCc2cIyCdqp0ROUksRz0pOLTc5iY2nraUheRUD1vRRneq7GeXOVNn7uXONg
oCGMjNwwCgYIKoZIzj0EAwIDRwAwRAIgDSiwgIn8g1lpruYH0QD1GYeoWVunfmrI
XzZZl0eW/ugCICgOfXeZ2GGy3wIC0352BaC3a8r5AAb2XSGNe+e9wNN6
-----END CERTIFICATE-----`

const invalidCNWithoutSAN = `-----BEGIN CERTIFICATE-----
MIIBJDCBywIUB7q8t9mrDAL+UB1OFaMN5BEWFKIwCgYIKoZIzj0EAwIwFDESMBAG
A1UECwwJVGVzdCByb290MB4XDTE4MDcxMTE4MzUyMVoXDTI4MDcwODE4MzUyMVow
FjEUMBIGA1UEAwwLZm9vLGludmFsaWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASnpnwiM6dHfwiTLV9hNS7aRWd28pdzGLABEkoa1bdvQTy7BWn0Bl3/6yunhQtM
90VOgUB6qcYdu7rZuSazylCQMAoGCCqGSM49BAMCA0gAMEUCIQCFlnW2cjxnEqB/
hgSB0t3IZ1DXX4XAVFT85mtFCJPTKgIgYIY+1iimTtrdbpWJzAB2eBwDgIWmWgvr
xfOcLt/vbvo=
-----END CERTIFICATE-----`

const validCNWithoutSAN = `-----BEGIN CERTIFICATE-----
MIIBJzCBzwIUB7q8t9mrDAL+UB1OFaMN5BEWFKQwCgYIKoZIzj0EAwIwFDESMBAG
A1UECwwJVGVzdCByb290MB4XDTE4MDcxMTE4NDcyNFoXDTI4MDcwODE4NDcyNFow
GjEYMBYGA1UEAwwPZm9vLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEp6Z8IjOnR38Iky1fYTUu2kVndvKXcxiwARJKGtW3b0E8uwVp9AZd/+sr
p4ULTPdFToFAeqnGHbu62bkms8pQkDAKBggqhkjOPQQDAgNHADBEAiBTbNe3WWFR
cqUYo0sNUuoV+tCTMDJUS+0PWIW4qBqCOwIgFHdLDn5PCk9kJpfc0O2qZx03hdq0
h7olHCpY9yMRiz0=
-----END CERTIFICATE-----`

const rootWithoutSKID = `-----BEGIN CERTIFICATE-----
MIIBbzCCARSgAwIBAgIQeCkq3C8SOX/JM5PqYTl9cDAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE5MDIwNDIyNTYzNFoXDTI5MDIwMTIyNTYzNFow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABISm
jGlTr4dLOWT+BCTm2PzWRjk1DpLcSAh+Al8eB1Nc2eBWxYIH9qPirfatvqBOA4c5
ZwycRpFoaw6O+EmXnVujTDBKMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBIGA1UdEQQLMAmCB2V4YW1wbGUwCgYI
KoZIzj0EAwIDSQAwRgIhAMaBYWFCjTfn0MNyQ0QXvYT/iIFompkIqzw6wB7qjLrA
AiEA3sn65V7G4tsjZEOpN0Jykn9uiTjqniqn/S/qmv8gIec=
-----END CERTIFICATE-----`

const leafWithAKID = `-----BEGIN CERTIFICATE-----
MIIBjTCCATSgAwIBAgIRAPCKYvADhKLPaWOtcTu2XYwwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHQWNtZSBDbzAeFw0xOTAyMDQyMzA2NTJaFw0yOTAyMDEyMzA2NTJa
MBMxETAPBgNVBAoTCEFjbWUgTExDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
Wk5N+/8X97YT6ClFNIE5/4yc2YwKn921l0wrIJEcT2u+Uydm7EqtCJNtZjYMAnBd
Acp/wynpTwC6tBTsxcM0s6NqMGgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUwitfkXg0JglCjW9R
ssWvTAveakIwEgYDVR0RBAswCYIHZXhhbXBsZTAKBggqhkjOPQQDAgNHADBEAiBk
4LpWiWPOIl5PIhX9PDVkmjpre5oyoH/3aYwG8ABYuAIgCeSfbYueOOG2AdXuMqSU
ZZMqeJS7JldLx91sPUArY5A=
-----END CERTIFICATE-----`

const rootMatchingSKIDMismatchingSubject = `-----BEGIN CERTIFICATE-----
MIIBQjCB6aADAgECAgEAMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBlJvb3QgQTAe
Fw0wOTExMTAyMzAwMDBaFw0xOTExMDgyMzAwMDBaMBExDzANBgNVBAMTBlJvb3Qg
QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPK4p1uXq2aAeDtKDHIokg2rTcPM
2gq3N9Y96wiW6/7puBK1+INEW//cO9x6FpzkcsHw/TriAqy4sck/iDAvf9WjMjAw
MA8GA1UdJQQIMAYGBFUdJQAwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHQ4EBQQDAQID
MAoGCCqGSM49BAMCA0gAMEUCIQDgtAp7iVHxMnKxZPaLQPC+Tv2r7+DJc88k2SKH
MPs/wQIgFjjNvBoQEl7vSHTcRGCCcFMdlN4l0Dqc9YwGa9fyrQs=
-----END CERTIFICATE-----`

const rootMismatchingSKIDMatchingSubject = `-----BEGIN CERTIFICATE-----
MIIBNDCB26ADAgECAgEAMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBlJvb3QgQjAe
Fw0wOTExMTAyMzAwMDBaFw0xOTExMDgyMzAwMDBaMBExDzANBgNVBAMTBlJvb3Qg
QjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1YRFcIlkWzm9BdEVrIsEQJ2dT6
qiW8/WV9GoIhmDtX9SEDHospc0Cgm+TeD2QYW2iMrS5mvNe4GSw0Jezg/bOjJDAi
MA8GA1UdJQQIMAYGBFUdJQAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNI
ADBFAiEAukWOiuellx8bugRiwCS5XQ6IOJ1SZcjuZxj76WojwxkCIHqa71qNw8FM
DtA5yoL9M2pDFF6ovFWnaCe+KlzSwAW/
-----END CERTIFICATE-----`

const leafMatchingAKIDMatchingIssuer = `-----BEGIN CERTIFICATE-----
MIIBNTCB26ADAgECAgEAMAoGCCqGSM49BAMCMBExDzANBgNVBAMTBlJvb3QgQjAe
Fw0wOTExMTAyMzAwMDBaFw0xOTExMDgyMzAwMDBaMA8xDTALBgNVBAMTBExlYWYw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNWERXCJZFs5vQXRFayLBECdnU+qol
vP1lfRqCIZg7V/UhAx6LKXNAoJvk3g9kGFtojK0uZrzXuBksNCXs4P2zoyYwJDAO
BgNVHSMEBzAFgAMBAgMwEgYDVR0RBAswCYIHZXhhbXBsZTAKBggqhkjOPQQDAgNJ
ADBGAiEAnV9XV7a4h0nfJB8pWv+pBUXRlRFA2uZz3mXEpee8NYACIQCWa+wL70GL
ePBQCV1F9sE2q4ZrnsT9TZoNrSe/bMDjzA==
-----END CERTIFICATE-----`

var unknownAuthorityErrorTests = []struct {
	cert     string
	expected string
}{
	{selfSignedWithCommonName, "x509: certificate signed by unknown authority (possibly because of \"empty\" while trying to verify candidate authority certificate \"test\")"},
	{selfSignedNoCommonNameWithOrgName, "x509: certificate signed by unknown authority (possibly because of \"empty\" while trying to verify candidate authority certificate \"ca\")"},
	{selfSignedNoCommonNameNoOrgName, "x509: certificate signed by unknown authority (possibly because of \"empty\" while trying to verify candidate authority certificate \"serial:0\")"},
}

func TestUnknownAuthorityError(t *testing.T) {
	for i, tt := range unknownAuthorityErrorTests {
		der, _ := pem.Decode([]byte(tt.cert))
		if der == nil {
			t.Errorf("#%d: Unable to decode PEM block", i)
		}
		c, err := ParseCertificate(der.Bytes)
		if err != nil {
			t.Errorf("#%d: Unable to parse certificate -> %v", i, err)
		}
		uae := &UnknownAuthorityError{
			Cert:     c,
			hintErr:  fmt.Errorf("empty"),
			hintCert: c,
		}
		actual := uae.Error()
		if actual != tt.expected {
			t.Errorf("#%d: UnknownAuthorityError.Error() response invalid actual: %s expected: %s", i, actual, tt.expected)
		}
	}
}

var nameConstraintTests = []struct {
	constraint, domain string
	expectError        bool
	shouldMatch        bool
}{
	{"", "anything.com", false, true},
	{"example.com", "example.com", false, true},
	{"example.com.", "example.com", true, false},
	{"example.com", "example.com.", true, false},
	{"example.com", "ExAmPle.coM", false, true},
	{"example.com", "exampl1.com", false, false},
	{"example.com", "www.ExAmPle.coM", false, true},
	{"example.com", "sub.www.ExAmPle.coM", false, true},
	{"example.com", "notexample.com", false, false},
	{".example.com", "example.com", false, false},
	{".example.com", "www.example.com", false, true},
	{".example.com", "www..example.com", true, false},
}

func TestNameConstraints(t *testing.T) {
	for i, test := range nameConstraintTests {
		result, err := matchDomainConstraint(test.domain, test.constraint)

		if err != nil && !test.expectError {
			t.Errorf("unexpected error for test #%d: domain=%s, constraint=%s, err=%s", i, test.domain, test.constraint, err)
			continue
		}

		if err == nil && test.expectError {
			t.Errorf("unexpected success for test #%d: domain=%s, constraint=%s", i, test.domain, test.constraint)
			continue
		}

		if result != test.shouldMatch {
			t.Errorf("unexpected result for test #%d: domain=%s, constraint=%s, result=%t", i, test.domain, test.constraint, result)
		}
	}
}

const selfSignedWithCommonName = `-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMQswCQYDVQQKEwJjYTEL
MAkGA1UEAxMCY2EwHhcNMTYwODI4MTcwOTE4WhcNMjEwODI3MTcwOTE4WjAcMQsw
CQYDVQQKEwJjYTENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAOH55PfRsbvmcabfLLko1w/yuapY/hk13Cgmc3WE/Z1ZStxGiVxY
gQVH9n4W/TbUsrep/TmcC4MV7xEm5252ArcgaH6BeQ4QOTFj/6Jx0RT7U/ix+79x
8RRysf7OlzNpGIctwZEM7i/G+0ZfqX9ULxL/EW9tppSxMX1jlXZQarnU7BERL5cH
+G2jcbU9H28FXYishqpVYE9L7xrXMm61BAwvGKB0jcVW6JdhoAOSfQbbgp7JjIlq
czXqUsv1UdORO/horIoJptynTvuARjZzyWatya6as7wyOgEBllE6BjPK9zpn+lp3
tQ8dwKVqm/qBPhIrVqYG/Ec7pIv8mJfYabMCAwEAAaNZMFcwDgYDVR0PAQH/BAQD
AgOoMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA
MAoGA1UdDgQDBAEAMAwGA1UdIwQFMAOAAQAwDQYJKoZIhvcNAQELBQADggEBAAAM
XMFphzq4S5FBcRdB2fRrmcoz+jEROBWvIH/1QUJeBEBz3ZqBaJYfBtQTvqCA5Rjw
dxyIwVd1W3q3aSulM0tO62UCU6L6YeeY/eq8FmpD7nMJo7kCrXUUAMjxbYvS3zkT
v/NErK6SgWnkQiPJBZNX1Q9+aSbLT/sbaCTdbWqcGNRuLGJkmqfIyoxRt0Hhpqsx
jP5cBaVl50t4qoCuVIE9cOucnxYXnI7X5HpXWvu8Pfxo4SwVjb1az8Fk5s8ZnxGe
fPB6Q3L/pKBe0SEe5GywpwtokPLB3lAygcuHbxp/1FlQ1NQZqq+vgXRIla26bNJf
IuYkJwt6w+LH/9HZgf8=
-----END CERTIFICATE-----`
const selfSignedNoCommonNameWithOrgName = `-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMQswCQYDVQQKEwJjYTEL
MAkGA1UEAxMCY2EwHhcNMTYwODI4MTgxMzQ4WhcNMjEwODI3MTgxMzQ4WjANMQsw
CQYDVQQKEwJjYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5EjrUa
7EtOMxWiIgTzp2FlQvncPsG329O3l3uNGnbigb8TmNMw2M8UhoDjd84pnU5RAfqd
8t5TJyw/ybnIKBN131Q2xX+gPQ0dFyMvcO+i1CUgCxmYZomKVA2MXO1RD1hLTYGS
gOVjc3no3MBwd8uVQp0NStqJ1QvLtNG4Uy+B28qe+ZFGGbjGqx8/CU4A8Szlpf7/
xAZR8w5qFUUlpA2LQYeHHJ5fQVXw7kyL1diNrKNi0G3qcY0IrBh++hT+hnEEXyXu
g8a0Ux18hoE8D6rAr34rCZl6AWfqW5wjwm+N5Ns2ugr9U4N8uCKJYMPHb2CtdubU
46IzVucpTfGLdaMCAwEAAaNZMFcwDgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQG
CCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMAoGA1UdDgQDBAEAMAwG
A1UdIwQFMAOAAQAwDQYJKoZIhvcNAQELBQADggEBAEn5SgVpJ3zjsdzPqK7Qd/sB
bYd1qtPHlrszjhbHBg35C6mDgKhcv4o6N+fuC+FojZb8lIxWzJtvT9pQbfy/V6u3
wOb816Hm71uiP89sioIOKCvSAstj/p9doKDOUaKOcZBTw0PS2m9eja8bnleZzBvK
rD8cNkHf74v98KvBhcwBlDifVzmkWzMG6TL1EkRXUyLKiWgoTUFSkCDV927oXXMR
DKnszq+AVw+K8hbeV2A7GqT7YfeqOAvSbatTDnDtKOPmlCnQui8A149VgZzXv7eU
29ssJSqjUPyp58dlV6ZuynxPho1QVZUOQgnJToXIQ3/5vIvJRXy52GJCs4/Gh/w=
-----END CERTIFICATE-----`
const selfSignedNoCommonNameNoOrgName = `-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgIBADANBgkqhkiG9w0BAQsFADAaMQswCQYDVQQKEwJjYTEL
MAkGA1UEAxMCY2EwHhcNMTYwODI4MTgxOTQ1WhcNMjEwODI3MTgxOTQ1WjAAMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp3E+Jl6DpgzogHUW/i/AAcCM
fnNJLOamNVKFGmmxhb4XTHxRaWoTzrlsyzIMS0WzivvJeZVe6mWbvuP2kZanKgIz
35YXRTR9HbqkNTMuvnpUESzWxbGWE2jmt2+a/Jnz89FS4WIYRhF7nI2z8PvZOfrI
2gETTT2tEpoF2S4soaYfm0DBeT8K0/rogAaf+oeUS6V+v3miRcAooJgpNJGu9kqm
S0xKPn1RCFVjpiRd6YNS0xZirjYQIBMFBvoSoHjaOdgJptNRBprYPOxVJ/ItzGf0
kPmzPFCx2tKfxV9HLYBPgxi+fP3IIx8aIYuJn8yReWtYEMYU11hDPeAFN5Gm+wID
AQABo1kwVzAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsG
AQUFBwMBMAwGA1UdEwEB/wQCMAAwCgYDVR0OBAMEAQAwDAYDVR0jBAUwA4ABADAN
BgkqhkiG9w0BAQsFAAOCAQEATZVOFeiCpPM5QysToLv+8k7Rjoqt6L5IxMUJGEpq
4ENmldmwkhEKr9VnYEJY3njydnnTm97d9vOfnLj9nA9wMBODeOO3KL2uJR2oDnmM
9z1NSe2aQKnyBb++DM3ZdikpHn/xEpGV19pYKFQVn35x3lpPh2XijqRDO/erKemb
w67CoNRb81dy+4Q1lGpA8ORoLWh5fIq2t2eNGc4qB8vlTIKiESzAwu7u3sRfuWQi
4R+gnfLd37FWflMHwztFbVTuNtPOljCX0LN7KcuoXYlr05RhQrmoN7fQHsrZMNLs
8FVjHdKKu+uPstwd04Uy4BR/H2y1yerN9j/L6ZkMl98iiA==
-----END CERTIFICATE-----`

const criticalExtRoot = `-----BEGIN CERTIFICATE-----
MIIBqzCCAVGgAwIBAgIJAJ+mI/85cXApMAoGCCqGSM49BAMCMB0xDDAKBgNVBAoT
A09yZzENMAsGA1UEAxMEUm9vdDAeFw0xNTAxMDEwMDAwMDBaFw0yNTAxMDEwMDAw
MDBaMB0xDDAKBgNVBAoTA09yZzENMAsGA1UEAxMEUm9vdDBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABJGp9joiG2QSQA+1FczEDAsWo84rFiP3GTL+n+ugcS6TyNib
gzMsdbJgVi+a33y0SzLZxB+YvU3/4KTk8yKLC+2jejB4MA4GA1UdDwEB/wQEAwIC
BDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB
/zAZBgNVHQ4EEgQQQDfXAftAL7gcflQEJ4xZATAbBgNVHSMEFDASgBBAN9cB+0Av
uBx+VAQnjFkBMAoGCCqGSM49BAMCA0gAMEUCIFeSV00fABFceWR52K+CfIgOHotY
FizzGiLB47hGwjMuAiEA8e0um2Kr8FPQ4wmFKaTRKHMaZizCGl3m+RG5QsE1KWo=
-----END CERTIFICATE-----`

const criticalExtIntermediate = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIJAL2kcGZKpzVqMAoGCCqGSM49BAMCMB0xDDAKBgNVBAoT
A09yZzENMAsGA1UEAxMEUm9vdDAeFw0xNTAxMDEwMDAwMDBaFw0yNTAxMDEwMDAw
MDBaMCUxDDAKBgNVBAoTA09yZzEVMBMGA1UEAxMMSW50ZXJtZWRpYXRlMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAESqVq92iPEq01cL4o99WiXDc5GZjpjNlzMS1n
rk8oHcVDp4tQRRQG3F4A6dF1rn/L923ha3b0fhDLlAvXZB+7EKN6MHgwDgYDVR0P
AQH/BAQDAgIEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNVHRMB
Af8EBTADAQH/MBkGA1UdDgQSBBCMGmiotXbbXVd7H40UsgajMBsGA1UdIwQUMBKA
EEA31wH7QC+4HH5UBCeMWQEwCgYIKoZIzj0EAwIDSAAwRQIhAOhhNRb6KV7h3wbE
cdap8bojzvUcPD78fbsQPCNw1jPxAiBOeAJhlTwpKn9KHpeJphYSzydj9NqcS26Y
xXbdbm27KQ==
-----END CERTIFICATE-----`

const criticalExtLeafWithExt = `-----BEGIN CERTIFICATE-----
MIIBxTCCAWugAwIBAgIJAJZAUtw5ccb1MAoGCCqGSM49BAMCMCUxDDAKBgNVBAoT
A09yZzEVMBMGA1UEAxMMSW50ZXJtZWRpYXRlMB4XDTE1MDEwMTAwMDAwMFoXDTI1
MDEwMTAwMDAwMFowJDEMMAoGA1UEChMDT3JnMRQwEgYDVQQDEwtleGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF3ABa2+B6gUyg6ayCaRQWYY/+No
6PceLqEavZNUeVNuz7bS74Toy8I7R3bGMkMgbKpLSPlPTroAATvebTXoBaijgYQw
gYEwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAMBgNVHRMBAf8EAjAAMBkGA1UdDgQSBBBRNtBL2vq8nCV3qVp7ycxMMBsGA1Ud
IwQUMBKAEIwaaKi1dttdV3sfjRSyBqMwCgYDUQMEAQH/BAAwCgYIKoZIzj0EAwID
SAAwRQIgVjy8GBgZFiagexEuDLqtGjIRJQtBcf7lYgf6XFPH1h4CIQCT6nHhGo6E
I+crEm4P5q72AnA/Iy0m24l7OvLuXObAmg==
-----END CERTIFICATE-----`

const criticalExtIntermediateWithExt = `-----BEGIN CERTIFICATE-----
MIIB2TCCAX6gAwIBAgIIQD3NrSZtcUUwCgYIKoZIzj0EAwIwHTEMMAoGA1UEChMD
T3JnMQ0wCwYDVQQDEwRSb290MB4XDTE1MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAw
MFowPTEMMAoGA1UEChMDT3JnMS0wKwYDVQQDEyRJbnRlcm1lZGlhdGUgd2l0aCBD
cml0aWNhbCBFeHRlbnNpb24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQtnmzH
mcRm10bdDBnJE7xQEJ25cLCL5okuEphRR0Zneo6+nQZikoh+UBbtt5GV3Dms7LeP
oF5HOplYDCd8wi/wo4GHMIGEMA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQKxdv
UuQZ6sO3XvBsxgNZ3zAbBgNVHSMEFDASgBBAN9cB+0AvuBx+VAQnjFkBMAoGA1ED
BAEB/wQAMAoGCCqGSM49BAMCA0kAMEYCIQCQzTPd6XKex+OAPsKT/1DsoMsg8vcG
c2qZ4Q0apT/kvgIhAKu2TnNQMIUdcO0BYQIl+Uhxc78dc9h4lO+YJB47pHGx
-----END CERTIFICATE-----`

const criticalExtLeaf = `-----BEGIN CERTIFICATE-----
MIIBzzCCAXWgAwIBAgIJANoWFIlhCI9MMAoGCCqGSM49BAMCMD0xDDAKBgNVBAoT
A09yZzEtMCsGA1UEAxMkSW50ZXJtZWRpYXRlIHdpdGggQ3JpdGljYWwgRXh0ZW5z
aW9uMB4XDTE1MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowJDEMMAoGA1UEChMD
T3JnMRQwEgYDVQQDEwtleGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABG1Lfh8A0Ho2UvZN5H0+ONil9c8jwtC0y0xIZftyQE+Fwr9XwqG3rV2g4M1h
GnJa9lV9MPHg8+b85Hixm0ZSw7SjdzB1MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAZBgNVHQ4EEgQQ
UNhY4JhezH9gQYqvDMWrWDAbBgNVHSMEFDASgBArF29S5Bnqw7de8GzGA1nfMAoG
CCqGSM49BAMCA0gAMEUCIQClA3d4tdrDu9Eb5ZBpgyC+fU1xTZB0dKQHz6M5fPZA
2AIgN96lM+CPGicwhN24uQI6flOsO3H0TJ5lNzBYLtnQtlc=
-----END CERTIFICATE-----`

func TestValidHostname(t *testing.T) {
	tests := []struct {
		host                     string
		validInput, validPattern bool
	}{
		{host: "example.com", validInput: true, validPattern: true},
		{host: "eXample123-.com", validInput: true, validPattern: true},
		{host: "-eXample123-.com"},
		{host: ""},
		{host: "."},
		{host: "example..com"},
		{host: ".example.com"},
		{host: "example.com.", validInput: true},
		{host: "*.example.com."},
		{host: "*.example.com", validPattern: true},
		{host: "*foo.example.com"},
		{host: "foo.*.example.com"},
		{host: "exa_mple.com", validInput: true, validPattern: true},
		{host: "foo,bar"},
		{host: "project-dev:us-central1:main"},
	}
	for _, tt := range tests {
		if got := validHostnamePattern(tt.host); got != tt.validPattern {
			t.Errorf("validHostnamePattern(%q) = %v, want %v", tt.host, got, tt.validPattern)
		}
		if got := validHostnameInput(tt.host); got != tt.validInput {
			t.Errorf("validHostnameInput(%q) = %v, want %v", tt.host, got, tt.validInput)
		}
	}
}

func generateCert(cn string, isCA bool, issuer *Certificate, issuerKey crypto.PrivateKey) (*Certificate, crypto.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              KeyUsageKeyEncipherment | KeyUsageDigitalSignature | KeyUsageCertSign,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if issuer == nil {
		issuer = template
		issuerKey = priv
	}

	derBytes, err := CreateCertificate(rand.Reader, template, issuer, priv.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func TestPathologicalChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	// Build a chain where all intermediates share the same subject, to hit the
	// path building worst behavior.
	roots, intermediates := NewCertPool(), NewCertPool()

	parent, parentKey, err := generateCert("Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 100; i++ {
		parent, parentKey, err = generateCert("Intermediate CA", true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert("Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = leaf.Verify(VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	t.Logf("verification took %v", time.Since(start))

	if err == nil || !strings.Contains(err.Error(), "signature check attempts limit") {
		t.Errorf("expected verification to fail with a signature checks limit error; got %v", err)
	}
}

func TestLongChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	roots, intermediates := NewCertPool(), NewCertPool()

	parent, parentKey, err := generateCert("Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 15; i++ {
		name := fmt.Sprintf("Intermediate CA #%d", i)
		parent, parentKey, err = generateCert(name, true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert("Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := leaf.Verify(VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		t.Error(err)
	}
	t.Logf("verification took %v", time.Since(start))
}

func TestSystemRootsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use (or support) systemRoots")
	}

	defer func(oldSystemRoots *CertPool) { systemRoots = oldSystemRoots }(systemRootsPool())

	opts := VerifyOptions{
		Intermediates: NewCertPool(),
		DNSName:       "www.google.com",
		CurrentTime:   time.Unix(1395785200, 0),
	}

	if ok := opts.Intermediates.AppendCertsFromPEM([]byte(giag2Intermediate)); !ok {
		t.Fatalf("failed to parse intermediate")
	}

	leaf, err := certificateFromPEM(googleLeaf)
	if err != nil {
		t.Fatalf("failed to parse leaf: %v", err)
	}

	systemRoots = nil

	_, err = leaf.Verify(opts)
	if _, ok := err.(SystemRootsError); !ok {
		t.Errorf("error was not SystemRootsError: %v", err)
	}
}
