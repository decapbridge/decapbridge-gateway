package api

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripCommitAuthor(t *testing.T) {
	t.Run("RemovesAuthorAndCommitter", func(t *testing.T) {
		body := `{"message":"Update post","tree":"abc123","parents":["def456"],"author":{"name":"Editor","email":"editor@example.com"},"committer":{"name":"Editor","email":"editor@example.com"}}`
		r, err := http.NewRequest(http.MethodPost, "/repos/org/repo/git/commits", bytes.NewReader([]byte(body)))
		require.NoError(t, err)
		stripCommitAuthor(r)
		out, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.NotContains(t, string(out), "author")
		assert.NotContains(t, string(out), "committer")
		assert.Contains(t, string(out), `"message":"Update post"`)
		assert.Contains(t, string(out), `"tree":"abc123"`)
		assert.Equal(t, int64(len(out)), r.ContentLength)
	})

	t.Run("PassesThroughInvalidJSON", func(t *testing.T) {
		body := `not json`
		r, err := http.NewRequest(http.MethodPost, "/repos/org/repo/git/commits", bytes.NewReader([]byte(body)))
		require.NoError(t, err)
		stripCommitAuthor(r)
		out, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(out))
	})
}
