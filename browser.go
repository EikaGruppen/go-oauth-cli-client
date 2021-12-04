package oauth

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

func OpenUrl(url *url.URL) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url.String()).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url.String()).Start()
	case "darwin":
		return exec.Command("open", url.String()).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

