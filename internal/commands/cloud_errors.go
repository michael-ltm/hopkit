package commands

import (
	"errors"
	"os"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/spf13/cobra"
)

type cloudDisplayError struct {
	cause   error
	message string
}

func (e *cloudDisplayError) Error() string { return e.message }
func (e *cloudDisplayError) Unwrap() error { return e.cause }

func friendlyCloudError(err error) error {
	if err == nil {
		return nil
	}
	var displayed *cloudDisplayError
	if errors.As(err, &displayed) {
		return err
	}
	var api *cloudsync.APIError
	if errors.As(err, &api) {
		return &cloudDisplayError{err, textUI(api.Message("en"), api.Message("zh-CN"))}
	}
	if errors.Is(err, cloudsync.ErrUnlock) {
		return &cloudDisplayError{err, textUI("could not unlock the vault; check the vault unlock phrase or recovery code (not the account password); vault data may also be damaged", "保险库解锁失败，请检查解锁口令或恢复码（不是账号密码）；也可能是保险库数据损坏")}
	}
	return err
}

func wrapCloudErrors(cmd *cobra.Command) {
	if run := cmd.RunE; run != nil {
		cmd.RunE = func(c *cobra.Command, args []string) error { return friendlyCloudError(run(c, args)) }
	}
	for _, child := range cmd.Commands() {
		wrapCloudErrors(child)
	}
}

func cloudStateLoadError(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return &cloudDisplayError{err, textUI("cloud account is not configured; run sshm cloud login, or sshm cloud register to create an account", "尚未配置云端账号，请运行 sshm cloud login 登录；没有账号请运行 sshm cloud register 注册")}
	}
	return &cloudDisplayError{err, textUI("could not read local cloud account data; check file permissions and preserve the state file before recovery", "无法读取本地云端账号数据，请检查文件权限，并在恢复前保留原有状态文件")}
}
