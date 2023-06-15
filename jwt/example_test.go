package jwt

import (
	"fmt"
	"testing"
	"time"
)

func Test_JWT(t *testing.T) {
	t.Skip()

	type fields struct {
		signingMethod SigningMethod
		privateKey    []byte
		publicKey     []byte
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
			name: "EdDSA",
			fields: fields{
				signingMethod: SigningMethodEdDSA,
				privateKey: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOF17froyQplFvkuHWfd8w+TDvZJaqa8Vb+8EYCXn1PJ
-----END PRIVATE KEY-----`),
				publicKey: []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjc7me3Kg+7KKVu+gri+xeN8CThJx/CwP7LnR5Ul5K9A=
-----END PUBLIC KEY-----`),
				expires: time.Hour,
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
			name: "RS256",
			fields: fields{
				signingMethod: SigningMethodRS256,
				privateKey: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA8fvrp9q9FTId/dBYmZ6KyBNFzetZf+WegGaW48qWgIDySUmm
9LcEVj8jEQrGcZL9L7WvOdi7TymKUNoFUhJPCWuN3dlCLB7J/SZU56cRgzWCinRT
UTF7GFBef4tl5T5dHK7wjpXnViHu8EqEXnwa5qaJx3gUMMWmvt+Q293qiVEDf0qm
KwElcpkDbpjwk0m8FzWGh3ch4eUU3YzwBoBRPHfnac81wWyw34p/kZpxM8Yf9Irs
5pXRlPl1oho1yZ/hjtFZtGrRKGZR3tsBewmwn1XqWWYJj28d1P/4Hg0npi5jLBkg
5GUesG6JNBd98izi25qDzqIkCgn8UbeOjzf+PwIDAQABAoIBAQDQBaQxGT6hAQN9
VWVFMmDV3JOOkPrQkwGuGgMu8dJtx+wBCrrm9opY5k/r75pmuljDcemfzexAAlLw
bGxUgH7Hd1lu1L0pFpLH9/LXbe0FIbQF+DhDvUi3vydtd9VxvCnpZY5Q1RcZGXTB
xx2B6ChsDdC11ElvIArXXXO3P0/HGFz4la2pzqFCOCGj6HNW1I5YIxHTYCtkdIBf
RYaJYLvGFpodHhV1ZhVC0VppabZ/8Rx4sx9XFY5eezFn4SRhYgqxegbHLcNN7VuI
S81vdugz6I5wE8NxZpG70Re3ePABHMfbBiFPDuYDq5WyUrJYxTOx1GCqnsQSPZpx
atTo5rwRAoGBAPtwA6KmEmm4Md/3qsu8qo9Ze0Q9Zow221xwIsQ1g5jsX4mpLvBq
n9htib1b9smvBl5sSbw2gCkQKkfan3b2BZhdjerInkMVon3HTw5a3Pg8Ui3p8dwi
4lTSufsPXgT+WSNR77NH3WjR2rEbfGj5xc9amGxtatBsbU+kBm9zHs9JAoGBAPZf
/h+ihW/Mxa4UzckXPKAahYuKM8dDHnSCq/H+0gwc2N0u9xfvGv0lo7rZdMeYfVcT
/uc9K1b919qLF8JrHinutI/othVFH0p+mMTy+rKfEpx+RnHulnxg4O3kSCUtYBNR
b29S2qHS2NCMkJwTwSqZvYtEl4zUAj8JwUmNG3lHAoGBAL7bqTbGXwW21s0Of6xF
WyaTItmKzhOy9FI3oHxVrr3e9ypUrRe7p/guNbbyXuN7Ixd7lYDz0dbZuW5vikpP
t7GPmlFU1aVQf9Z/+weHe2JGz46gnYGfTTRb/OaRJKofs+P2pz/sVinh2eJEXeyF
ZFzghQEREVqCY3tno6bnuMRZAoGAKvgW9CF+MD+AgpnyQg4hbrLxc6LI4Qndt+hK
YMxWifJGCF12juAOzvPPmHjwmxcHVTaRkHbkpiljiiQUIr5X5mxRZX/qsc76ZB2s
Oz09aAXCUzTayGgaKtsin5re0k0VoojjbIEAzJRfaA/78JypZeqmWjG+VLttIN1s
ro1Dq2UCgYEA4kuk0L/gJpcrOVac2N45oVXQyL14IM9EP/7TInYx93++JkveWm3h
lAeojK6Uyf+ekwKPw7qEMwh3Av/SWeG5jtupJ7eL355WivHzf6tl773wx6I4Ggn7
UULG8nAHfeihcoAprLcv5hYHbEt2BWqNA4O1Wtk0o/0A2EvlI6vm74E=
-----END RSA PRIVATE KEY-----`),
				publicKey: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8fvrp9q9FTId/dBYmZ6K
yBNFzetZf+WegGaW48qWgIDySUmm9LcEVj8jEQrGcZL9L7WvOdi7TymKUNoFUhJP
CWuN3dlCLB7J/SZU56cRgzWCinRTUTF7GFBef4tl5T5dHK7wjpXnViHu8EqEXnwa
5qaJx3gUMMWmvt+Q293qiVEDf0qmKwElcpkDbpjwk0m8FzWGh3ch4eUU3YzwBoBR
PHfnac81wWyw34p/kZpxM8Yf9Irs5pXRlPl1oho1yZ/hjtFZtGrRKGZR3tsBewmw
n1XqWWYJj28d1P/4Hg0npi5jLBkg5GUesG6JNBd98izi25qDzqIkCgn8UbeOjzf+
PwIDAQAB
-----END PUBLIC KEY-----`),
				expires: time.Hour,
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
			name: "ES256",
			fields: fields{
				signingMethod: SigningMethodES256,
				privateKey: []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIB8himEk4YtMU0Z40qifJ6F8COXA7e03FWpDW4mf/ryeoAoGCCqGSM49
AwEHoUQDQgAETm4/o9XmNkSZtXZQ9lKxb3mpLSuVQfOQn8U/vy3zpfZ/Ndq8xLdZ
TPEv4KfWivw/1ecHsYvFqWxCLyQBpTtUjQ==
-----END EC PRIVATE KEY-----`),
				publicKey: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETm4/o9XmNkSZtXZQ9lKxb3mpLSuV
QfOQn8U/vy3zpfZ/Ndq8xLdZTPEv4KfWivw/1ecHsYvFqWxCLyQBpTtUjQ==
-----END PUBLIC KEY-----`),
				expires: time.Hour,
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
			name: "HS256",
			fields: fields{
				signingMethod: SigningMethodHS256,
				privateKey:    []byte(`[Your hmac key]`),
				publicKey:     []byte(`[Your hmac key]`),
				expires:       time.Hour,
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
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenGenerator() error = %v", err)
				return
			}

			tokenStr, err := g.Generate(tt.args.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			fmt.Println(tokenStr)

			verifier, err := NewTokenVerifier(tt.fields.signingMethod, tt.fields.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTokenVerifier() error = %v", err)
				return
			}

			info, err := verifier.Verify(tokenStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v", err)
				return
			}

			if info.UserID != tt.args.info.UserID {
				t.Errorf("verify token info: error = %v", err)
				return
			}

		})
	}
}
