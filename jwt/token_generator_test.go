package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestNewTokenGenerator(t *testing.T) {
	tokenGen, err := NewTokenGenerator(
		SigningMethodEdDSA,
		[]byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEFMEZrmlYzczXKFxIlNvNGR5JQvDhTkLevJYxwQd3ub
-----END PRIVATE KEY-----`),
		WithExpires(time.Second*30),
	)

	if err != nil {
		t.Errorf("NewTokenGenerator() error = %v", err)
		return
	}
	if tokenGen == nil {
		t.Errorf("NewTokenGenerator() = %v, want %v", tokenGen, nil)
	}
}

func TestTokenGenerator_Generate(t *testing.T) {
	t.Skip()

	type fields struct {
		signingMethod SigningMethod
		privateKey    []byte
		expires       time.Duration
	}
	type args struct {
		info TokenInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test EdDSA token generate",
			fields: fields{
				signingMethod: SigningMethodEdDSA,
				privateKey: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEFMEZrmlYxczXKFxIlNvNGR5JQvDhTkLovJYxwQd3ua
-----END PRIVATE KEY-----`),
				expires: time.Hour * 24 * 36500,
			},
			args: args{
				info: TokenInfo{
					UserID: 1,
					RoleID: 2,
				},
			},
			wantErr: false,
		},
		{
			name: "test HS256 token generate",
			fields: fields{
				signingMethod: SigningMethodHS256,
				privateKey:    []byte(`this-is-a-hs256-private-key`),
				expires:       time.Hour * 24 * 36500,
			},
			args: args{
				info: TokenInfo{
					UserID: 1,
					RoleID: 2,
				},
			},
			wantErr: false,
		},
		{
			name: "test RS256 token generate",
			fields: fields{
				signingMethod: SigningMethodRS256,
				privateKey: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvHYBVetGj74QZuVEUEWU6h17Ss2oa1175YiYm0IZuIZdiNbz
93oOUTz0KkQucTOS83O0aAEx9h+RVNt7OqKT0lHq2BCZ9Bj7nimjKhekE+KtYwQz
/VpGcz/R7NgdzbX8vU182MPe6y3SDENnMsfgHz6Jld08doNPXY2zI2Om5VDFzgMj
ThkvTMQ1HEHJUCJIUwmX50Ot5m48k4/l4aLzI8nA1uYV/eXcK0O4NZWpE2vmhddJ
hxblDq5t5nzq3r2vgM+2MX37egD5cYuO/DRiydPdiW51n6TRXDID6kuyT8NnGNAd
rCAewVRWLsRUKnufb7OtzQf4i0QjJtNUk3kqcQIDAQABAoIBAQC5qD60l6zRmlmq
JB3iPknvQM/e5y8NZfDSNHiyKrIP+D5YuflpSRKlsTiQEs71sesIbmnBM7w2TO7s
+7MwFk0tmomSBPjFYX8vVrFonBWFiX9p1hApfC9/BdYWTuk9aBTtoFJncL5ATMlq
T1Rw0DrYTNFZk7MmxUEAVsGtEVSu/eyW8EaY1M+tbkH/fgVqFWstl6a0R2+mUEnI
fiULB10dLWmir5xFOfjiNw3eQD614ALSFCm7WjybD6GXne+CmbG0iJRD48TG2uC/
7s9U4+1LjGBHhFXP7mDIJuH88cPZ/WRs+xT4ezJETy20zQcPoDH8D4bIkXxaE6QF
0q7euKGpAoGBAOFDyWJKJXJDblZ0elZc15NGPDbf+/ovYRWuswjTVYHKnT4q+eXO
Y+FyhlExhXzt9FtgQ8kv0dY8SryRp8Nzqbu3CQdwZynhvFR/yTGaClxfBqGGLZvD
Cjxr3ox6Um3QorOZsnAZtAq2brXaXNB6oLMCYu8vi/IvpumqrEc8geBjAoGBANYs
tRSzPT4wet39f5CLyhRmkhcoSyr5CkffjsBT041zjlwlPoiGx8gwSlERQDwL11Ld
WbiyKu1yGyCW4vC+hjxLaZ/mGZmCQTxfFL2IR8l3bZpWO/PlY9Hfoks14HleiXWn
c6KpWSM7LeE3TAlHeowis1jsfFSZvZqUGXTrp4AbAoGBAMMJtQiEGC35kkQKr42s
7v3VtvbwMbQpZ46lZuACUquA6WpVPW8qprIhPYh5LxG+2W5wR+CepbkvFKp2FmIU
9+XOkWO+f6P0jeI/jcyDier2X8Bkc4LEeU1dPCA3HL12AhksvyFuL8OCtxJ/ERN0
yUSUkWJ0sV+swIDaRDWdfvnvAoGAW2cPDLuF2oGUHiMuisCtyFER7eIbWkaYVZ4Z
7QiZU1fKnJakfl2O62d4f+pt0HJ5PXsL7F/VJCq7Wwgp5/ZXkWnZtQzdRf8p2hr1
3gFIKbnXQ7OjuG3gUNQxDgn7N7DZ1yVUm0nMqdV6uhAAWkFwElhI1B1w3iYSneKw
jo53mJsCgYEA0mHg7CvHnjx4D6yNa08YBbflD+jtcPoFVI8jb1c16Uwy4+k38aHc
5DHe2QTvKnWjOSDoOJ6L+ReNREo7t7Jn2WL3ICazVqQOUNRsM8DG0eoNgCdPieLx
9QV1LoXKui2iY88WTo2pfcpiE1TtenKrpe60powoioNLgEbLFMWg8Ms=
-----END RSA PRIVATE KEY-----`),
				expires: time.Hour * 24 * 36500,
			},
			args: args{
				info: TokenInfo{
					UserID: 1,
					RoleID: 2,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewTokenGenerator(tt.fields.signingMethod, tt.fields.privateKey, WithExpires(tt.fields.expires))
			if err != nil {
				t.Errorf("NewTokenGenerator() error = %v", err)
				return
			}

			got, err := g.Generate(tt.args.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenGenerator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			fmt.Println(got)
		})
	}
}
