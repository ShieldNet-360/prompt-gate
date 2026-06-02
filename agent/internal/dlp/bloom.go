// Public-example bloom layer in the DLP pipeline.
//
// IsPublicExample returns true if a candidate value matches a curated
// set of well-known public examples — AWS docs canonical key, Stripe
// test keys, PCI test card numbers, RFC 4122 documentation UUIDs, the
// jwt.io canonical token, etc. These values appear in tutorials,
// READMEs, and Stack Overflow answers and routinely cause false
// positives in pattern-based DLP. Matched values should never trigger
// a block.
//
// Storage: SHA-256 hashes only — original values are not embedded.
// Hashes are computed over a normalized form (whitespace, dashes, and
// underscores stripped; ASCII lowercased) so that "4111 1111 1111 1111",
// "4111-1111-1111-1111", and "4111111111111111" collide.
//
// Privacy invariant: this layer is a pure string-in / bool-out check.
// No disk I/O, no logging, no per-event state.

package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// normalizeForBloom strips whitespace, dashes, and underscores and
// ASCII-lowercases the input. Other Unicode characters pass through.
func normalizeForBloom(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '-', '_':
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 32
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hashForBloom returns the lowercase hex SHA-256 of the normalized
// form of s.
func hashForBloom(s string) string {
	h := sha256.Sum256([]byte(normalizeForBloom(s)))
	return hex.EncodeToString(h[:])
}

// IsPublicExample reports whether value is a known public example
// value. Matched values are excluded from DLP block decisions.
//
// Returns false for empty input.
func IsPublicExample(value string) bool {
	if value == "" {
		return false
	}
	_, ok := publicExampleHashes[hashForBloom(value)]
	return ok
}

// publicExampleHashes is the curated set of normalized SHA-256 hashes
// for well-known public examples. Each entry's trailing comment names
// the source value for auditability.
var publicExampleHashes = map[string]struct{}{
	// AWS documentation canonical examples
	"2eb6c6020c2290c8d9020b570bd9d6ef7577109b2d51c2510b61674ca782ee18": {}, // AKIAIOSFODNN7EXAMPLE
	"9b4d1fe07ab0b901c8c549a3431f4cd95ffb0149cbbbd41a37026098e0a857c0": {}, // wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
	"fcc070589dd4e6aebb0419707762410c066860353dd1a2a6d3dab1775c0c36b0": {}, // AKIAI44QH8DHBEXAMPLE

	// Stripe test keys
	"812992bb0cd8301ed7ec407e312ef1ffefa413fb39b7b5ea29715efbe557a784": {}, // sk_test_4eC39HqLyjWDarjtT1zdp7dc
	"81725703670b0b981181748791820f26997d3ac56e1dbc508ca3152d2e959694": {}, // pk_test_TYooMQauvdEDq54NiTphI7jx
	"bf90d859b5cf18b9c2edd0572e93be3ba8617d42f11b38f9a08c3d8e16fc067d": {}, // sk_test_BQokikJOvBiI2HlWgH4olfQ2
	"d4f3b9b9662f8683b74a505a9692a32847846d49106a13173c1acb14b4240241": {}, // rk_test_50tlPgJ65xQ8Hk88OF0EVx0p

	// PCI test card numbers (industry-standard)
	"9bbef19476623ca56c17da75fd57734dbf82530686043a6e491c6d71befe8f6e": {}, // 4111-1111-1111-1111 Visa
	"477bba133c182267fe5f086924abdc5db71f77bfc27f01f2843f2cdc69d89f05": {}, // 4242-4242-4242-4242 Stripe
	"dd13cdf9af9dd3baf46ce96aecd7163cabf381ccb21e63f15f0fa10b1c663fa9": {}, // 4012-8888-8888-1881 Visa
	"2f725bbd1f405a1ed0336abaf85ddfeb6902a9984a76fd877c3b5cc3b5085a82": {}, // 5555-5555-5555-4444 Mastercard
	"304945e91de3deff52a61d08733141d72dd42ec9d47972f1060534d54c0c7f90": {}, // 5105-1051-0510-5100 Mastercard
	"3a134ef77d4e2e4cdad2d2945ff1f76c1a23296c93c851f6244220a8cedea130": {}, // 378282246310005      Amex
	"53a8fc816e63b7a5ccd17aaff93f28bcf13abbf418209dcd93947722d7c326ba": {}, // 371449635398431      Amex
	"19ff47cc8024c133d5845d3f8938caca289929031e7d508c3adf7adff177f0c2": {}, // 6011-1111-1111-1117  Discover
	"51a4ae4c6ae999146474a67cbcb3b05fbcf4c17ab683043a066459da95513ea8": {}, // 30569309025904       Diners
	"1c9d38ed26cd808fa3b02b9b3b988a7caf474e2e42d95789c0fe07e267c80d8f": {}, // 3530111333300000     JCB

	// SSN-shape placeholders
	"f120bb5698d520c5691b6d603a00bfd662d13bf177a04571f9d10c0745dfa2a5": {}, // 000-00-0000
	"1a5376ad727d65213a79f3108541cf95012969a0d3064f108b5dd6e7f8c19b89": {}, // 111-11-1111
	"15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225": {}, // 123-45-6789
	"8a9bcf1e51e812d0af8465a8dbcc9f741064bf0af3b3d08e6b0246437c19f7fb": {}, // 987-65-4321

	// Documentation UUIDs (RFC 4122 examples + nil + all-ones)
	"84e0c0eafaa95a34c293f278ac52e45ce537bab5e752a00e6959a13ae103b65a": {}, // 00000000-0000-0000-0000-000000000000
	"140f39b05a2d9de451b9b7ad2d1f4a26b16fb5e5c8b7cbde6154679102614882": {}, // 550e8400-e29b-41d4-a716-446655440000
	"8a83665f3798727f14f92ad0e6c99fdab08ee731d6cd644c131223fd2f4fed2a": {}, // 11111111-1111-1111-1111-111111111111
	"352302489bc2fcf025cf00cda8308033f97ac87712ce90b4d7cd72c58e4c3af9": {}, // ffffffff-ffff-ffff-ffff-ffffffffffff
	"f61cf167454b8f32635f585ae94699fc670a44bca48d6350a4361bca1752ab0b": {}, // a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11

	// jwt.io canonical example token
	"4de2692a4f508164d09c5aa954d9d965d9f5ed47b0551b1b7cebdf7384ba4411": {}, // eyJhbGc...SflKxwRJ...

	// GitHub PAT placeholder shapes
	"d804c5614dcc743c75e4863b8bf47775bbdb724205d02771d8ff27802a40a053": {}, // ghp_xxxxxxxxxxxxxxxxxxxx
	"c83e4aa7782ef61c65f0e467b61ad55645c6b59f1cc0e103213393c702b4b41f": {}, // ghs_xxxxxxxxxxxxxxxxxxxx
}
