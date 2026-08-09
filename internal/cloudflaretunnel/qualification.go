package cloudflaretunnel

func QualificationConfiguration() []byte {
	return []byte("ingress:\n  - hostname: xhttp.example.com\n    service: http://127.0.0.1:11080\n  - hostname: ws.example.com\n    service: http://127.0.0.1:11081\n  - service: http_status:404\n")
}
