// Package gosh provides a simple SSH client for Go.
package gosh

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	// DefaultUsername default user of ssh client connection.
	DefaultUsername = "root"

	// DefaultTimeout default timeout of ssh client connection.
	DefaultTimeout = 20 * time.Second

	// DefaultPort default port of ssh client connection.
	DefaultPort     = 22
	DefaultProtocol = "tcp"
)

// Options for SSH Client.
type Options struct {
	Username      string
	Password      string
	Key           string
	KeyPassphrase string
	Addr          string
	Port          int
	UseAgent      bool
	Timeout       time.Duration
}

// NewOptions creates an Options with default parameters.
func NewOptions() *Options {
	return &Options{
		Username: DefaultUsername,
		Port:     DefaultPort,
		Timeout:  DefaultTimeout,
	}
}

// Client SSH client.
type Client struct {
	*ssh.Client

	opts     *Options
	auth     ssh.AuthMethod
	callback ssh.HostKeyCallback
}

// NewDefault creates a Client with DefaultHostKeyCallback, the host public key must be in known hosts.
func NewDefault(opts *Options) (*Client, error) {
	callback, err := DefaultHostKeyCallback()
	if err != nil {
		return nil, err
	}
	cli, err := New(opts)
	if err != nil {
		return nil, err
	}
	cli.WithHostKeyCallback(callback)
	return cli, nil
}

// NewInsecure creates a Client that does not verify the server keys.
func NewInsecure(opts *Options) (*Client, error) {
	cli, err := New(opts)
	if err != nil {
		return nil, err
	}
	//nolint:gosec
	cli.WithHostKeyCallback(ssh.InsecureIgnoreHostKey())
	return cli, nil
}

// New creates a Client without ssh.HostKeyCallback.
func New(opts *Options) (*Client, error) {
	var (
		auth ssh.AuthMethod
		err  error
	)

	auth, err = Auth(opts)
	if err != nil {
		return nil, err
	}

	c := &Client{
		opts: opts,
		auth: auth,
		callback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	return c, nil
}

// WithHostKeyCallback sets ssh.HostKeyCallback of Client.
func (c *Client) WithHostKeyCallback(callback ssh.HostKeyCallback) *Client {
	c.callback = callback
	return c
}

// Dial starts a client connection to the given SSH server.
func (c *Client) Dial() error {
	cli, err := c.dial()
	if err != nil {
		return err
	}
	c.Client = cli

	return nil
}

// Ping alias for Dial.
func (c *Client) Ping() error {
	return c.Dial()
}

// CombinedOutput runs cmd on the remote host and returns its combined
// standard output and standard error.
func (c *Client) CombinedOutput(command string) ([]byte, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, err
	}

	defer func() { _ = session.Close() }()

	return session.CombinedOutput(command)
}

// CombinedOutputContext is like CombinedOutput but includes a context.
//
// The provided context is used to kill the process (by calling
// os.Process.Kill) if the context becomes done before the command
// completes on its own.
func (c *Client) CombinedOutputContext(ctx context.Context, command string) ([]byte, error) {
	cmd, err := c.CommandContext(ctx, command)
	if err != nil {
		return nil, err
	}
	return cmd.CombinedOutput()
}

// Command returns the Cmd struct to execute the named program with
// the given arguments.
//
// It sets only the Path and Args in the returned structure.
func (c *Client) Command(name string, args ...string) (*Cmd, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	return newCommand(session, name, args...), nil
}

// CommandContext is like Command but includes a context.
//
// The provided context is used to kill the process (by calling
// os.Process.Kill) if the context becomes done before the command
// completes on its own.
func (c *Client) CommandContext(ctx context.Context, name string, args ...string) (*Cmd, error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	return newCommandContext(ctx, session, name, args...), nil
}

// NewSftp returns new sftp client and error if any.
func (c *Client) NewSftp(opts ...sftp.ClientOption) (*sftp.Client, error) {
	return sftp.NewClient(c.Client, opts...)
}

// Upload equivalent to the command `scp <src> <host>:<dst>`.
func (c *Client) Upload(src, dst string) error {
	local, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = local.Close() }()

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer func() { _ = ftp.Close() }()

	remote, err := ftp.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = remote.Close() }()

	_, err = io.Copy(remote, local)
	return err
}

// Download equivalent to the command `scp <host>:<src> <dst>`.
func (c *Client) Download(src, dst string) error {
	local, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = local.Close() }()

	ftp, err := c.NewSftp()
	if err != nil {
		return err
	}
	defer func() { _ = ftp.Close() }()

	remote, err := ftp.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = remote.Close() }()

	if _, err = io.Copy(local, remote); err != nil {
		return err
	}

	return local.Sync()
}

// ReadFile reads the file named by filename and returns the contents.
func (c *Client) ReadFile(src string) ([]byte, error) {
	ftp, err := c.NewSftp()
	if err != nil {
		return nil, err
	}
	defer func() { _ = ftp.Close() }()

	f, err := ftp.Open(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	chunks := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		at, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if at == 0 {
			break
		}
		chunks = append(chunks, buf[:at]...)
	}
	return chunks, nil
}

// Close client ssh connection.
func (c *Client) Close() error {
	if c.Client != nil {
		return c.Client.Close()
	}
	return nil
}

func (c *Client) dial() (*ssh.Client, error) {
	return ssh.Dial(DefaultProtocol,
		net.JoinHostPort(c.opts.Addr, strconv.Itoa(c.opts.Port)),
		&ssh.ClientConfig{
			User:            c.opts.Username,
			Auth:            []ssh.AuthMethod{c.auth},
			Timeout:         c.opts.Timeout,
			HostKeyCallback: c.callback,
		},
	)
}

func Ping(addr, user, password, key string, port int) error {
	if port < 1 {
		port = DefaultPort
	}
	cli, err := NewInsecure(&Options{
		Username: user,
		Password: password,
		Key:      key,
		Addr:     addr,
		Port:     port,
	})
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()
	return cli.Ping()
}
