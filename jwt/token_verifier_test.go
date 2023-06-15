package jwt

import (
	"testing"
)

func TestTokenVerifier_Verify(t *testing.T) {
	type fields struct {
		signingMethod SigningMethod
		PublicKey     []byte
	}
	type args struct {
		tokenStr string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *TokenInfo
		wantErr bool
	}{
		{
			name: "test EdDSA token verify",
			fields: fields{
				signingMethod: SigningMethodEdDSA,
				PublicKey: []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWH7z6hpYqvPns2i4n9yymwvB3APhi4LyQ7iHOT6crtE=
-----END PUBLIC KEY-----`),
			},
			args: args{
				tokenStr: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlX2lkIjoyLCJpc3MiOiJ0ZXN0IiwiZXhwIjo0ODA2NjI3OTg2LCJuYmYiOjE2NTMwMjc5ODYsImlhdCI6MTY1MzAyNzk4Nn0.zwnayiLnDfuwsh8ACxkACxq-R__r8uYZnMicqWl7iqRJl20QyyN2pFUWBptPX-jtv_yN03DNr3hjlnCi19PMAQ",
			},
			want: &TokenInfo{
				UserID: 1,
				RoleID: 2,
			},
			wantErr: false,
		},
		{
			name: "test HS256 token verify",
			fields: fields{
				signingMethod: SigningMethodHS256,
				PublicKey:     []byte(`this-is-a-hs256-private-key`),
			},
			args: args{
				tokenStr: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlX2lkIjoyLCJpc3MiOiJ0ZXN0IiwiZXhwIjo0ODA2NjI3OTg2LCJuYmYiOjE2NTMwMjc5ODYsImlhdCI6MTY1MzAyNzk4Nn0.seYmGgYa_mhSgPFjzfzFZQCdiGd99NXeRb8XvIFrwtM",
			},
			want: &TokenInfo{
				UserID: 1,
				RoleID: 2,
			},
			wantErr: false,
		},
		{
			name: "test RS256 token verify",
			fields: fields{
				signingMethod: SigningMethodRS256,
				PublicKey: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvHYBVetGj74QZuVEUEWU
6h17Ss2oa1175YiYm0IZuIZdiNbz93oOUTz0KkQucTOS83O0aAEx9h+RVNt7OqKT
0lHq2BCZ9Bj7nimjKhekE+KtYwQz/VpGcz/R7NgdzbX8vU182MPe6y3SDENnMsfg
Hz6Jld08doNPXY2zI2Om5VDFzgMjThkvTMQ1HEHJUCJIUwmX50Ot5m48k4/l4aLz
I8nA1uYV/eXcK0O4NZWpE2vmhddJhxblDq5t5nzq3r2vgM+2MX37egD5cYuO/DRi
ydPdiW51n6TRXDID6kuyT8NnGNAdrCAewVRWLsRUKnufb7OtzQf4i0QjJtNUk3kq
cQIDAQAB
-----END PUBLIC KEY-----`),
			},
			args: args{
				tokenStr: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlX2lkIjoyLCJpc3MiOiJ0ZXN0IiwiZXhwIjo0ODA2NjI4MTA1LCJuYmYiOjE2NTMwMjgxMDUsImlhdCI6MTY1MzAyODEwNX0.pW9S0IhaRVfKpqHlt95lA20v_aVJSWznBHqIq9s7sNT0HkgPor7L92h4gh79201j7yX3qyUCrN-ZnQkUzuXTyjVazYK4SJRvkEHXdek4dRHCUnxGvOvwI9XSes4oSOYSgBR1tMq05cJh5UWDwlORBJ410gGSIs08usfA0byGTh-_NWgM7S9d2hM6rHYkj2rq1sT7UguZ2MY0idl_XfT17xc65yGL6SxLRBpDBhBiFjcOAB7PIPCwyeBoW1ssEIV_ITa8i8DsgabABNF_WyYU7CxZzYWqxSh7ZzPRvcTpeUYKHejJc0NfGTV-7wJ5SntEI5EpEXBK0G9ZCaBZNtIvQQ",
			},
			want: &TokenInfo{
				UserID: 1,
				RoleID: 2,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewTokenVerifier(tt.fields.signingMethod, tt.fields.PublicKey)
			if err != nil {
				t.Errorf("NewTokenVerifier() error = %v", err)
				return
			}
			got, err := v.Verify(tt.args.tokenStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenVerifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.UserID != tt.want.UserID || got.RoleID != tt.want.RoleID {
				t.Errorf("TokenVerifier.Verify() got = %v, want %v", got, tt.want)
			}
		})
	}
}
