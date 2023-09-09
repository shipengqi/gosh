package gssh

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	addr   string
	user   string
	passwd string
	key    string
)

const (
	_testUser = "testuser"
	_testPass = "testpass"
	_testAddr = "127.0.10.10"
)

func TestGSSH(t *testing.T) {
	t.Run("TestPassAuth", secure(t, authTest))
	t.Run("Ping", func(t *testing.T) {
		err := Ping(addr, user, passwd, key)
		assert.NoError(t, err)
	})
	t.Run("Ping error", func(t *testing.T) {
		err := Ping(addr, user, "errorpass", key)
		if err != nil {
			assert.Contains(t, err.Error(), "ssh: unable to authenticate")
		}
	})

}

func TestGSSHInsecure(t *testing.T) {
	t.Run("TestPassAuth", insecure(t, authTest))
	t.Run("TestCmdOutPipe", insecure(t, outPipeTest))
	t.Run("TestSetEnv", insecure(t, envTest))
	t.Run("TestClientCmd", insecure(t, cliCmdTest))
	t.Run("TestUpload", insecure(t, uploadTest))
	t.Run("TestReadFile", insecure(t, readFileTest))
	t.Run("TestDownload", insecure(t, downloadTest))
}

func TestMain(m *testing.M) {
	flag.StringVar(&addr, "addr", "", "The host of ssh")
	flag.StringVar(&user, "user", "", "The username of client")
	flag.StringVar(&passwd, "pass", "", "The password of user")
	flag.StringVar(&key, "ssh-key", "", "The location of private key")

	flag.Parse()
	if addr == "" {
		addr = _testUser
		user = _testPass
		passwd = _testAddr
		newSSHServer()
	}
	os.Exit(m.Run())
}

func insecure(t *testing.T, callback func(t *testing.T, cli *Client)) func(t *testing.T) {
	opts := NewOptions()
	opts.Username = user
	opts.Password = passwd
	opts.Addr = addr
	opts.Key = key

	cli, err := NewInsecure(opts)
	assert.NoError(t, err)
	err = cli.Dial()
	assert.NoError(t, err)
	return func(t *testing.T) {
		callback(t, cli)
	}
}

func secure(t *testing.T, callback func(t *testing.T, cli *Client)) func(t *testing.T) {
	opts := NewOptions()
	opts.Username = user
	opts.Password = passwd
	opts.Addr = addr
	opts.Key = key

	cli, err := New(opts)
	assert.NoError(t, err)
	cli.WithHostKeyCallback(AutoFixedHostKeyCallback)
	err = cli.Dial()
	assert.NoError(t, err)
	return func(t *testing.T) {
		defer func() { _ = cli.Close() }()
		callback(t, cli)
	}
}

func uploadTest(t *testing.T, cli *Client) {
	ftp, _ := cli.NewSftp()
	_ = ftp.Remove("/tmp/upload.txt")
	err := cli.Upload("./testdata/upload.txt", "/tmp/upload.txt")
	assert.NoError(t, err)
}

func readFileTest(t *testing.T, cli *Client) {
	data, err := cli.ReadFile("/tmp/upload.txt")
	assert.NoError(t, err)
	assert.Equal(t, "uploaded", string(data))
}

func downloadTest(t *testing.T, cli *Client) {
	err := cli.Download("/tmp/upload.txt", "./testdata/download.txt")
	assert.NoError(t, err)
	data, err := os.ReadFile("./testdata/download.txt")
	assert.NoError(t, err)
	assert.Equal(t, "uploaded", string(data))
	_ = os.Remove("./testdata/download.txt")
	ftp, _ := cli.NewSftp()
	_ = ftp.Remove("/tmp/upload.txt")
}

func cliCmdTest(t *testing.T, cli *Client) {
	output, err := cli.CombinedOutput("echo \"Hello, world!\"")
	assert.NoError(t, err)

	assert.Equal(t, "Hello, world!\n", string(output))
}

func authTest(t *testing.T, cli *Client) {
	cmd, err := cli.Command("echo", "Hello, world!")
	assert.NoError(t, err)

	output, err := cmd.Output()
	assert.NoError(t, err)

	assert.Equal(t, "Hello, world!\n", string(output))
}

func outPipeTest(t *testing.T, cli *Client) {
	cmd, err := cli.Command("n=1;while [ $n -le 4 ];do echo $n;((n++));done")
	assert.NoError(t, err)
	var lines []string
	err = cmd.OutputPipe(func(reader io.Reader) error {
		nreader := bufio.NewReader(reader)
		for {
			line, _, rerr := nreader.ReadLine()
			if rerr != nil || io.EOF == rerr {
				break
			}
			lines = append(lines, string(line))
			if err != nil {
				return err
			}
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []string{"1", "2", "3", "4"}, lines)
}

func envTest(t *testing.T, cli *Client) {
	cmd, err := cli.Command("echo", "Hello, $TEST_ENV_NAME!")
	assert.NoError(t, err)
	err = cmd.Setenv([]string{"TEST_ENV_NAME=GSSH"})
	assert.NoError(t, err)
	output, err := cmd.Output()
	assert.NoError(t, err)

	assert.Equal(t, "Hello, GSSH!\n", string(output))
}

var _testPrivateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArn3wx2StZXegLcEkRz9Tf71C2mZ8RPUbLzO8l54N3UqEI4GF
mscjlpm/L1CCYU46nYyAwMskL1hAgPTym3AjLeCDImvdz1286fUPTyu1T4MGKOQh
6pDNGcgkbAOCUttoI7rWik+YhZbBZoTTikjfcZjMyhQdAwI808HV8z8nKHSCpEFO
4VQBOz4isRLkaK3lt6KmPPSY5YUt3aENIfnv5MmxtLj4SGfVncsiiDR6gPHFtqCF
428Es75646bMQ+HSPRQnjcIpFqIz1qB6M0uXfeUge/2sPQH8lAddtva3yEZ8ZjfU
WZB1aFO53fzfZLSZ0Gm/KpwkOszIaXOvRxbXqQIDAQABAoIBAQCN4bfr2dAoZknn
ilneWP6jKph2j8jSJV8yVWYu/oSVgGbLnCCwBubIKUHMzjEFwB9nRfzXRxaoLKFe
ek3e2CKyxhC652yXlcfrkKkfHhIykf5rN3zgh1dOdHAxJ/VLPD6EdwLFugzx6vBd
VPnRQon1i2JRmmMwtBwTr1QxkxNbD3GKVoB/yMy029tg3OSMyF8O8GzmvaYRUMBY
1nWDVIMWpt1oy+5UYEY2y+s6sE8g6lqHxFYk42ex68tUZI6sIN8e6GUfuEmZQ4bW
3czmeffV2tByROGf/4+JNa7HoTRQvbalru7v0QjB196ckUmeCdVnjymspAVxf1Wk
R/8f/r0BAoGBAN76wZ5K8GrL0Qqn16bkS5TU60FVjYkgFGnMXilj2VgzB+AJ0a68
kYf9iMohdE70qi5G1P01jEiCHmv0/VlEF2OJAqCyMJosWnu58kVYjW1nVWIGLnwd
mCCOr+WfqKgcQrG/8JZujaKS42xX6c2oeBLypSnbaevsOt1lqfOs616hAoGBAMhV
AEsha4HO/UF7QL0n7nubJOghBhqA6Ff9OYoTwOoJ8H6LtGcdBAUedtfeG6wypPln
aahjqokD7WMSxO67euubuCc0b4jsA4fjPaoYNyHcGAH/x0f3K2jnZHzsHzVIXFKR
Jv/RZ+gMfBDMlUuH09dDlzLkEY6kTF6010czlgQJAoGAbnCsrYZYhczlgO2Y9mRk
uxaqXvXM4HovIifDC6UU5YaBBApY/L8RJdYBhnwDa4frMniKzc9T6CXqg3YYdbow
C3C1CHq5b+M//cAfqxEtG17u/1ooc/kEfDuwC3+EvZ8huYBj3V5scHVohyUT/HTQ
5DGidJTkZaHflgDgqHyhJ4ECgYBbcMETiguiUrKyoumn7YQjk2tDMV+x1Uk4cHNF
HUMfEK5fdLFBp7LgC0m/urfy36MB3DwUCnoa1FoUsMqHFbhDtu5Vps+KNgBelFDf
RPJVWDr1HqT9qkp8NbJeewC7t228mlisyA6fkqNGn7s9oKAHT+jB5+xDqabaS70/
2MIO0QKBgFt5okxrothRXmxxzO2U3hcFBCZAtRXkj0REJrMtICQw29h38bmvpdm9
LrK3B3eRWTSYzuq5QST13bWuQn8lx4jBh8wd2sKWcB/NKedHHMtJZtTNogO86vue
YCqEboHwm82jJkbEn3A33yJzm7dGI+/79kvrrT591hhyer8z6a2W
-----END RSA PRIVATE KEY-----`)

func newSSHServer() {

	config := &ssh.ServerConfig{
		// Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in a production setting.
			if c.User() == _testUser && string(pass) == _testPass {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	// generate a keypair with 'ssh-keygen -t rsa'
	private, err := ssh.ParsePrivateKey(_testPrivateKey)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", _testAddr+":2200")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	go func() {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Fatal("failed to handshake: ", err)
		}
		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}()
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		// only handle the session type
		_ = newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	go func(in <-chan *ssh.Request) {
		for req := range in {
			switch req.Type {
			case "exec":
				// just return error 0 without exec.
				_, _ = connection.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			}
			_ = req.Reply(req.Type == "exec", nil)
		}
	}(requests)

	term := terminal.NewTerminal(connection, "> ")

	go func() {
		defer func() { _ = connection.Close() }()
		for {
			line, err := term.ReadLine()
			if err != nil {
				break
			}
			log.Println(line)
		}
	}()
}
