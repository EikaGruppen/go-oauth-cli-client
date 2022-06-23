package oauth

import (
	"embed"
	"html/template"
	"io"
)

//go:embed callback.html
var callbackPage embed.FS

type CallbackPage struct {
	Title   string
	Heading string
	Message string
}

var successPage = CallbackPage{
	Title:   "Successfully authorized!",
	Heading: "Successfully authorized!",
	Message: "You may now close this window and return to the terminal",
}

var errorPage = CallbackPage{
	Title:   "Authorization failed!",
	Heading: "Failed to authorize!",
	Message: "Head back to the terminal for error description. You may close this window",
}

func writeSuccessPage(w io.Writer, errChan chan<- error) {
	templ, err := template.ParseFS(callbackPage, "callback.html")
	if err != nil {
		io.WriteString(w, successPage.Message)
	}
	err = templ.Execute(w, successPage)
	if err != nil {
		errChan <- err
	}
}

func writeErrorPage(w io.Writer, errChan chan<- error) {
	templ, err := template.ParseFS(callbackPage, "callback.html")
	if err != nil {
		io.WriteString(w, errorPage.Message)
	}
	err = templ.Execute(w, errorPage)
	if err != nil {
		errChan <- err
	}
}
