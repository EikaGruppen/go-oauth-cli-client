package oauth

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

type Browser interface {
	// Opens a browser with the specified url. Should be thread safe
	Open(urls []*url.URL) error

	// If not nil, ran in a goroutine after callback has gotten the code
	Destroy() error
}

type DefaultBrowser struct {
}

func (d *DefaultBrowser) Open(urls []*url.URL) error {
	var errs []error
	for _, url := range urls {
		err := open(url)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("Open default browser failed: %v", errs)
	}
	return nil
}

func (d *DefaultBrowser) Destroy() error {
	return nil
}

func open(url *url.URL) error {
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
