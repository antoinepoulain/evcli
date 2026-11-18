// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/veraison/psatoken"
)

func Test_CreateCmd_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CreateCmd_WithP1Claims_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidP1PSAClaims, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
			"--profile=PSA_IOT_PROFILE_1",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CreateCmd_allowInivalid_ok(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
			"--allow-invalid",
		},
	)

	err = cmd.Execute()
	assert.NoError(t, err)
}

func Test_CreateCmd_claims_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `open claims.json: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_key_not_found(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error loading signing key from es256.jwk: open es256.jwk: file does not exist`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_token_file_write_failed(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	// freeze the FS so that writing is not possible anymore
	fs = afero.NewReadOnlyFs(fs)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--key=es256.jwk",
			"--claims=claims.json",
		},
	)

	expectedErr := `error saving PSA attestation token to file claims.cbor: operation not permitted`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_claims_profile_mismatch(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--key=es256.jwk",
			"--claims=claims.json",
			"--profile=PSA_IOT_PROFILE_1",
		},
	)

	expectedErr := `profile mismatch: requested: PSA_IOT_PROFILE_1 loaded: http://arm.com/psa/2.0.0`

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_unknown_profile(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--key=es256.jwk",
			"--claims=claims.json",
			"--profile=UNKNOWN_PROFILE_3",
		},
	)

	expectedErr := "wrong profile UNKNOWN_PROFILE_3: allowed profiles are http://arm.com/psa/2.0.0, PSA_IOT_PROFILE_1 and tag:psacertified.org,2023:psa#tfm"

	err = cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_CreateCmd_bad_key(t *testing.T) {
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "claims.json", testValidP2PSAClaimsWithNonce, 0644)
	require.NoError(t, err)

	err = afero.WriteFile(fs, "es256.jwk", testInvalidKey, 0644)
	require.NoError(t, err)

	cmd := NewCreateCmd(fs)
	cmd.SetArgs(
		[]string{
			"--claims=claims.json",
			"--key=es256.jwk",
		},
	)

	expectedErr := `error decoding signing key from es256.jwk: failed to parse key`

	err = cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}

func Test_CreateCmd_RFC9783_Profile_Mismatch(t *testing.T) {
    fs := afero.NewMemMapFs()

    // Existing claims use the PSA 2.0 profile.
    err := afero.WriteFile(
        fs, "claims.json",
        testValidP2PSAClaimsWithNonce, 0644,
    )
    require.NoError(t, err)

    err = afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
    require.NoError(t, err)

    cmd := NewCreateCmd(fs)
    cmd.SetArgs([]string{
        "--claims=claims.json",
        "--key=es256.jwk",
        "--profile=" + psatoken.RFC9783ProfileName,
        "--token=token.cbor",
    })

    err = cmd.Execute()

    expectedErr := "profile mismatch: requested: " + psatoken.RFC9783ProfileName + " loaded: " + psatoken.Profile2Name

    require.EqualError(t, err, expectedErr)

    // No token should have been created.
    exists, err := afero.Exists(fs, "token.cbor")
    require.NoError(t, err)
    require.False(t, exists)
}

func Test_CreateCmd_WithRFC9783Claims_ok(t *testing.T) {
    fs := afero.NewMemMapFs()

    err := afero.WriteFile(fs, "es256.jwk", testValidKey, 0644)
    require.NoError(t, err)

    err = afero.WriteFile(fs, "claims.json", testValidRFC9783Claims, 0644)
    require.NoError(t, err)

    cmd := NewCreateCmd(fs)
    cmd.SetArgs([]string{
        "--claims=claims.json",
        "--key=es256.jwk",
        "--profile=tag:psacertified.org,2023:psa#tfm",
        "--token=token.cbor",
    })

    err = cmd.Execute()
    require.NoError(t, err)

    token, err := afero.ReadFile(fs, "token.cbor")
    require.NoError(t, err)
    require.NotEmpty(t, token)
}


func Test_CheckProfile(t *testing.T) {
    tests := []struct {
        name    string
        profile string
        valid   bool
    }{
        {
            name:    "PSA Profile 1",
            profile: psatoken.Profile1Name,
            valid:   true,
        },
        {
            name:    "PSA Profile 2",
            profile: psatoken.Profile2Name,
            valid:   true,
        },
        {
            name:    "RFC 9783",
            profile: psatoken.RFC9783ProfileName,
            valid:   true,
        },
        {
            name:    "Unknown profile",
            profile: "UNKNOWN_PROFILE",
            valid:   false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := checkProfile(&tt.profile)

            if tt.valid {
                require.NoError(t, err)
            } else {
                require.Error(t, err)
            }
        })
    }

    t.Run("Nil profile", func(t *testing.T) {
        require.Error(t, checkProfile(nil))
    })
}

