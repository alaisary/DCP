package utils

import "net/http"

func SetUserAgent(inner http.RoundTripper, userAgent string) http.RoundTripper {
	return &UserAgentWrapper{
		inner: inner,
		Agent: userAgent,
	}
}

type UserAgentWrapper struct {
	inner http.RoundTripper
	Agent string
}

func (ug *UserAgentWrapper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("User-Agent", ug.Agent)
	inner := ug.inner

	if inner == nil {
		inner = http.DefaultTransport
	}

	return inner.RoundTrip(r)
}
