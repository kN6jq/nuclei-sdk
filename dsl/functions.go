package dsl

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
)

const alphaBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const alnumBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func urlDecode(s string) string {
	decoded, _ := url.QueryUnescape(s)
	return decoded
}

func hexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

func randAlphaString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphaBytes[int(b[i])%len(alphaBytes)]
	}
	return string(b)
}

func randAlnumString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alnumBytes[int(b[i])%len(alnumBytes)]
	}
	return string(b)
}

// toBase64 encodes a string to base64.
func toBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// fromBase64 decodes a base64 string.
func fromBase64(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// randTextAlpha generates a random alphabetic string of length n.
func randTextAlpha(n int) string {
	if n <= 0 {
		n = 8
	}
	return randAlphaString(n)
}

// randTextAlphanumeric generates a random alphanumeric string of length n.
func randTextAlphanumeric(n int) string {
	if n <= 0 {
		n = 12
	}
	return randAlnumString(n)
}

// randBase generates a random alphanumeric string of length n.
func randBase(n int) string {
	if n <= 0 {
		n = 8
	}
	return randAlnumString(n)
}

// Helper functions for language-aware case conversion (used by to_lower/to_upper in DSL)
func toLowerCase(s string) string {
	return strings.ToLower(s)
}

func toUpperCase(s string) string {
	return strings.ToUpper(s)
}

// length returns the length of a string as a float64 (for DSL compatibility).
func length(s string) float64 {
	return float64(len(s))
}

// Helper to convert int to float64
func intToFloat(i int) float64 {
	return float64(i)
}

// Helper to convert string to int
func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}