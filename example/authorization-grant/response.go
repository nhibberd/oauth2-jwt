package main

import "formation.engineering/library/lib/telemetry/v1"

type Response struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func Forbidden() Response {
	return Response{
		StatusCode: 403,
		Headers:    nil,
	}
}

func Ok(payload string) Response {
	return Response{
		StatusCode: 200,
		Headers:    nil,
		Body:       payload,
	}
}

func (x Response) Event(b telemetry.Builder) {
	b.Int("code", x.StatusCode)
	if x.StatusCode >= 200 && x.StatusCode < 300 {
		b.Bool("success", true)
	} else {
		b.Bool("success", false)
		// assume the body contains some description of the error
		b.String("response_body", x.Body)
	}
}
