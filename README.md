# gosh

A simple SSH client for Go. Inspired by [melbahja/goph](https://github.com/melbahja/goph).
Migrated from [golib](https://github.com/shipengqi/golib).

[![Go Report Card](https://goreportcard.com/badge/github.com/shipengqi/gosh)](https://goreportcard.com/report/github.com/shipengqi/gosh)
[![release](https://img.shields.io/github/release/shipengqi/gosh.svg)](https://github.com/shipengqi/gosh/releases)
[![license](https://img.shields.io/github/license/shipengqi/gosh)](https://github.com/shipengqi/gosh/blob/main/LICENSE)

## Getting Started

Run a command via ssh:
```go
package main

import (
	"context"
	"log"
	"time"
	
	"github.com/shipengqi/gosh"
)

func main() {

	// Creates an Options with default parameters.
	opts := gosh.NewOptions()
	// Start connection with private key
	opts.Key = "your private key"
	
	// Start connection with password
	// opts.Username = "your username"
	// opts.Password = "your password"
	
	// Start connection with SSH agent (Unix systems only):
	// opts.UseAgent = true
	
	// Creates a Client that does not verify the server keys
	cli, err := gosh.NewInsecure(opts)
	if err != nil {
		log.Fatal(err)
	}
	err = cli.Dial()
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	
	cmd, err := cli.Command("echo", "Hello, world!")
	if err != nil {
		log.Fatal(err)
	}
	// Executes your command and returns its standard output.
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(output))

	// Executes your command with context.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	cmd, err = cli.CommandContext(ctx, "echo", "Hello, world!")
	if err != nil {
		log.Fatal(err)
	}

	output, err = cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(output))
}
```

### Upload Local File to Remote:

```go
err := client.Upload("/path/to/local/file", "/path/to/remote/file")
```

### Download Remote File to Local:

```go
err := client.Download("/path/to/remote/file", "/path/to/local/file")
```

### ReadFile Read Remote File:

```go
data, err := client.ReadFile("/path/to/remote/file")
```

### Execute Bash Commands:

```go
output, _ := client.CombinedOutput("echo \"Hello, world!\"")
```

### Setenv

To set the environment variables in the ssh session using the `Setenv` method, it is important to note that
This needs to be added to the SSH server side configuration `/etc/ssh/sshd_config`, as follows

```bash
AcceptEnv EXAMPLE_ENV_NAME
```

### File System Operations Via SFTP:

```go
// Create a sftp with options
sftp, _ := cli.NewSftp()
file, _ := sftp.Create("/tmp/remote_file")

file.Write([]byte(`Hello world`))
file.Close()
```
For more file operations see [SFTP Docs](https://github.com/pkg/sftp).

## Documentation

You can find the docs at [go docs](https://pkg.go.dev/github.com/shipengqi/gosh).

## Test

Test with password:

```bash
go test -v . -addr <host> -user <username> -pass <password>
```

Test with private key:

```bash
go test -v . -addr <host> -ssh-key <private key>
```
