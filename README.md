# GlobalSign DSS Go Client SDK
Client SDK for GlobalSign Digital Signing Service API.

# Requirements
- mTLS certificate
- Private Key that used to generate mTLS
- API credentials

# Usage
Example usage:
- For [unidoc](https://unidoc.io "Unidoc website") integration see **_examples/main.go**.
```go
...

// Create GlobalSign client.
client, err := globalsign.NewClient("<API_KEY>", "<API_SECRET>", "<KEY_PATH>", "<CERT_PATH>")
if err != nil {
	return err
}

// Create signature handler.
handler, err := sign_handler.NewGlobalSignDSS(context.Background(), manager, option.SignedBy, map[string]interface{}{
	"common_name": "UniDoc"
})
if err != nil {
	return err
}
```

# Credits
Thanks to [@wja-id](https://github.com/wja-id)  

This package is modified from [https://github.com/wja-id/globalsign-sdk](https://github.com/wja-id/globalsign-sdk)