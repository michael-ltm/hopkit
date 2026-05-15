package wizard

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateAlias(t *testing.T) {
	require.NoError(t, ValidateAlias("my-host"))
	require.Error(t, ValidateAlias(""))
	require.Error(t, ValidateAlias("has space"))
	require.Error(t, ValidateAlias("CAPS"))
	require.Error(t, ValidateAlias("a/b"))
}

func TestValidateHost(t *testing.T) {
	require.NoError(t, ValidateHost("1.2.3.4"))
	require.NoError(t, ValidateHost("example.com"))
	require.Error(t, ValidateHost(""))
}

func TestValidatePort(t *testing.T) {
	require.NoError(t, ValidatePort("22"))
	require.NoError(t, ValidatePort("65535"))
	require.Error(t, ValidatePort(""))
	require.Error(t, ValidatePort("abc"))
	require.Error(t, ValidatePort("0"))
	require.Error(t, ValidatePort("65536"))
}
