package dlp

import "testing"

func TestClassifyContent_Code(t *testing.T) {
	src := `package main

import "fmt"
import "os"

func main() {
	fmt.Println(os.Args)
}`
	if got := ClassifyContent(src); got != CodeContent {
		t.Fatalf("Go source classified as %q, want %q", got, CodeContent)
	}

	py := `from collections import defaultdict
def foo(x):
    return x

class Bar:
    pass`
	if got := ClassifyContent(py); got != CodeContent {
		t.Fatalf("Python source classified as %q, want %q", got, CodeContent)
	}
}

func TestClassifyContent_Structured(t *testing.T) {
	j := `{"user": "alice", "id": 42, "tags": ["a", "b"]}`
	if got := ClassifyContent(j); got != StructuredData {
		t.Fatalf("JSON classified as %q, want %q", got, StructuredData)
	}

	csv := `name,age,city
alice,30,nyc
bob,25,sfo
carol,40,la
dan,35,bos`
	if got := ClassifyContent(csv); got != StructuredData {
		t.Fatalf("CSV classified as %q, want %q", got, StructuredData)
	}
}

func TestClassifyContent_Credentials(t *testing.T) {
	creds := `AWS_ACCESS_KEY_ID=AKIA1234
AWS_SECRET_ACCESS_KEY=secret
DATABASE_URL=postgres://user:pw@host
API_TOKEN=abcdef`
	if got := ClassifyContent(creds); got != CredentialsBlock {
		t.Fatalf("env-style creds classified as %q, want %q", got, CredentialsBlock)
	}
}

func TestClassifyContent_NaturalLanguage(t *testing.T) {
	prose := `This is a paragraph of plain English text with many spaces and ordinary words ` +
		`and sentences ending in periods. There are no curly braces and no equals signs ` +
		`and no obvious import or class declarations.`
	if got := ClassifyContent(prose); got != NaturalLanguage {
		t.Fatalf("prose classified as %q, want %q", got, NaturalLanguage)
	}

	if got := ClassifyContent(""); got != NaturalLanguage {
		t.Fatalf("empty classified as %q, want %q", got, NaturalLanguage)
	}
}
