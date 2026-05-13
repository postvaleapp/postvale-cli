package output

import "testing"

func TestShouldFail(t *testing.T) {
	cases := []struct {
		grade string
		want  bool
	}{
		{"A+", false},
		{"A", false},
		{"B", false},
		{"C", true},
		{"D", true},
		{"F", true},
		{"", true},
		{"unknown", true},
	}
	for _, tc := range cases {
		if got := ShouldFail(tc.grade); got != tc.want {
			t.Errorf("ShouldFail(%q) = %v, want %v", tc.grade, got, tc.want)
		}
	}
}
