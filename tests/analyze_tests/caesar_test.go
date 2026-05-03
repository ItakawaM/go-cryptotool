package analyze_test

import (
	"testing"

	"github.com/ItakawaM/arcipher/ciphers"
	"github.com/ItakawaM/arcipher/ciphers/analyze"
)

func TestCaesarAnalyzer_AnalyzeBuffer(t *testing.T) {
	tests := []struct {
		name    string
		buffer  []byte
		want    int
		wantErr bool
	}{
		{
			name: "moby dick",
			buffer: []byte(`Aol Wyvqlja Nbaluilyn lIvvr vm Tvif Kpjr; Vy, Aol Dohsl
    
Aopz livvr pz mvy aol bzl vm hufvul hufdolyl pu aol Bupalk Zahalz huk
tvza vaoly whyaz vm aol dvysk ha uv jvza huk dpao hstvza uv ylzaypjapvuz
dohazvlcly. Fvb thf jvwf pa, npcl pa hdhf vy yl-bzl pa bukly aol alytz
vm aol Wyvqlja Nbaluilyn Spjluzl pujsbklk dpao aopz livvr vy vuspul
ha ddd.nbaluilyn.vyn. Pm fvb hyl uva svjhalk pu aol Bupalk Zahalz,
fvb dpss ohcl av joljr aol shdz vm aol jvbuayf dolyl fvb hyl svjhalk
ilmvyl bzpun aopz lIvvr.

Apasl: Tvif Kpjr; Vy, Aol Dohsl

Hbaovy: Olythu Tlscpssl

Ylslhzl khal: Qbsf 1, 2001 [lIvvr #2701]
                Tvza yljluasf bwkhalk: Mliybhyf 10, 2026

Shunbhnl: Lunspzo

Jylkpaz: Khupls Shghybz, Qvulzlf, huk Khcpk Dpknly


*** ZAHYA VM AOL WYVQLJA NBALUILYN LIVVR TVIF KPJR; VY, AOL DOHSL ***




TVIF-KPJR;

vy, AOL DOHSL.`),
			want: 7,
		},
		{
			name: "plain mody dick",
			buffer: []byte(`The Project Gutenberg eBook of Moby Dick; Or, The Whale
    
This ebook is for the use of anyone anywhere in the United States and
most other parts of the world at no cost and with almost no restrictions
whatsoever. You may copy it, give it away or re-use it under the terms
of the Project Gutenberg License included with this ebook or online
at www.gutenberg.org. If you are not located in the United States,
you will have to check the laws of the country where you are located
before using this eBook.
`),
			want: 0,
		},
		{
			name:    "empty",
			buffer:  []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := analyze.NewCaesarAnalyzer()
			got, gotErr := analyzer.AnalyzeBuffer(tt.buffer)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("AnalyzeBuffer() failed: %v", gotErr)
				}
				return
			}

			if tt.wantErr {
				t.Fatal("AnalyzeBuffer() succeeded unexpectedly")
			}

			if int(got[0].Key) != tt.want {
				t.Errorf("AnalyzeBuffer() = %v, want %v", got[0].Key, tt.want)
			}
		})
	}
}

func TestCaesarAnalyzer_AnalyzeBuffer_AllKeys(t *testing.T) {
	plaintext := []byte(`The Project Gutenberg eBook of Moby Dick; Or, The Whale
    
This ebook is for the use of anyone anywhere in the United States and
most other parts of the world at no cost and with almost no restrictions
whatsoever.
`)
	analyzer := analyze.NewCaesarAnalyzer()
	buffer := make([]byte, len(plaintext))
	for i := range 26 {
		cipher := ciphers.NewCaesarCipher(&ciphers.CaesarKey{
			Key: i,
		})
		if err := cipher.EncryptBlock(buffer, plaintext); err != nil {
			t.Fatalf("EncryptBlock() failed: %v", err)
		}

		got, gotErr := analyzer.AnalyzeBuffer(buffer)
		if gotErr != nil {
			t.Errorf("AnalyzeBuffer() failed: %v", gotErr)
		}

		if int(got[0].Key) != i {
			t.Errorf("AnalyzeBuffer() = %v, want %v", got[0].Key, i)
		}
	}
}
