package api

import (
	"net/http"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/netlify/git-gateway/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJWTClaimsCopiesConfig(t *testing.T) {
	base := &conf.Configuration{}
	base.JWT.Secret = "test-secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &GatewayClaims{
		AppMetaData: map[string]interface{}{
			"git_provider":       "github",
			"repo":               "org/repo",
			"access_token":       "tok",
			"hide_commit_author": true,
		},
	})
	signed, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	r, err := http.NewRequest(http.MethodPost, "/github/git/commits", nil)
	require.NoError(t, err)
	r = r.WithContext(withConfig(r.Context(), base))

	a := &API{}
	ctx, err := a.parseJWTClaims(signed, r)
	require.NoError(t, err)

	cfg := getConfig(ctx)
	assert.Equal(t, "org/repo", cfg.GitHub.Repo)
	assert.Equal(t, "tok", cfg.GitHub.AccessToken)
	assert.True(t, cfg.GitHub.HideCommitAuthor)

	assert.Empty(t, base.GitHub.Repo)
	assert.Empty(t, base.GitHub.AccessToken)
	assert.False(t, base.GitHub.HideCommitAuthor)
}
