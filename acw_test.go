package lanzou

import "testing"

func TestCalcAcwScV2(t *testing.T) {
	arg1 := "5D8776F79D6F46531729E68EEC1B548C74AB4569"
	got, err := CalcAcwScV2(arg1)
	if err != nil {
		t.Fatal(err)
	}
	want := "6a5e6435d9adf16ee27366c45ecfbdf7300b478e"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
