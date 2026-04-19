package storage

import "testing"

func TestRequireVerifyingSSLMode(t *testing.T) {
	cases := []struct {
		name    string
		connStr string
		wantErr bool
	}{
		// URL form
		{"url verify-full ok", "postgres://u:p@h/db?sslmode=verify-full", false},
		{"url verify-ca ok", "postgresql://u:p@h/db?sslmode=verify-ca", false},
		{"url no sslmode rejected", "postgres://u:p@h/db", true},
		{"url sslmode=prefer rejected", "postgres://u:p@h/db?sslmode=prefer", true},
		{"url sslmode=require rejected", "postgres://u:p@h/db?sslmode=require", true},
		{"url sslmode=disable rejected", "postgres://u:p@h/db?sslmode=disable", true},

		// keyword=value form
		{"kv verify-full ok", "host=h user=u dbname=d sslmode=verify-full", false},
		{"kv verify-ca ok", "host=h user=u dbname=d sslmode=verify-ca", false},
		{"kv no sslmode rejected", "host=h user=u dbname=d", true},
		{"kv sslmode=disable rejected", "host=h user=u dbname=d sslmode=disable", true},
		{"kv quoted sslmode ok", "host=h sslmode='verify-full'", false},
		{"kv case-insensitive key ok", "host=h SSLMODE=verify-full", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireVerifyingSSLMode(tc.connStr)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", tc.connStr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for %q, got %v", tc.connStr, err)
			}
		})
	}
}
