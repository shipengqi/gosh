package gosh_test

import (
	"bufio"
	"flag"
	"io"
	"os"
	"testing"

	"github.com/shipengqi/gosh"
	"github.com/stretchr/testify/assert"
)

var (
	addr   string
	user   string
	passwd string
	key    string
)

func TestGSSH(t *testing.T) {
	t.Run("TestPassAuth", secure(t, authTest))
	t.Run("Ping", func(t *testing.T) {
		err := gosh.Ping(&gosh.Options{
			Username: user,
			Password: passwd,
			Key:      key,
			Addr:     addr,
		})
		assert.NoError(t, err)
	})
	t.Run("Ping error", func(t *testing.T) {
		err := gosh.Ping(&gosh.Options{
			Username: user,
			Password: "error",
			Key:      key,
			Addr:     addr,
		})
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

func insecure(t *testing.T, callback func(t *testing.T, cli *gosh.Client)) func(t *testing.T) {
	opts := gosh.NewOptions()
	opts.Username = user
	opts.Password = passwd
	opts.Addr = addr
	opts.Key = key

	cli, err := gosh.NewInsecure(opts)
	assert.NoError(t, err)
	err = cli.Dial()
	assert.NoError(t, err)
	return func(t *testing.T) {
		callback(t, cli)
	}
}

func secure(t *testing.T, callback func(t *testing.T, cli *gosh.Client)) func(t *testing.T) {
	opts := gosh.NewOptions()
	opts.Username = user
	opts.Password = passwd
	opts.Addr = addr
	opts.Key = key

	cli, err := gosh.New(opts)
	assert.NoError(t, err)
	cli.WithHostKeyCallback(gosh.AutoFixedHostKeyCallback)
	err = cli.Dial()
	assert.NoError(t, err)
	return func(t *testing.T) {
		defer func() { _ = cli.Close() }()
		callback(t, cli)
	}
}

func uploadTest(t *testing.T, cli *gosh.Client) {
	ftp, _ := cli.NewSftp()
	_ = ftp.Remove("/tmp/upload.txt")
	err := cli.Upload("./testdata/upload.txt", "/tmp/upload.txt")
	assert.NoError(t, err)
}

func readFileTest(t *testing.T, cli *gosh.Client) {
	data, err := cli.ReadFile("/tmp/upload.txt")
	assert.NoError(t, err)
	assert.Equal(t, "uploaded", string(data))
}

func downloadTest(t *testing.T, cli *gosh.Client) {
	err := cli.Download("/tmp/upload.txt", "./testdata/download.txt")
	assert.NoError(t, err)
	data, err := os.ReadFile("./testdata/download.txt")
	assert.NoError(t, err)
	assert.Equal(t, "uploaded", string(data))
	_ = os.Remove("./testdata/download.txt")
	ftp, _ := cli.NewSftp()
	_ = ftp.Remove("/tmp/upload.txt")
}

func cliCmdTest(t *testing.T, cli *gosh.Client) {
	output, err := cli.CombinedOutput("echo \"Hello, world!\"")
	assert.NoError(t, err)

	assert.Equal(t, "Hello, world!\n", string(output))
}

func authTest(t *testing.T, cli *gosh.Client) {
	cmd, err := cli.Command("echo", "Hello, world!")
	assert.NoError(t, err)

	output, err := cmd.Output()
	assert.NoError(t, err)

	assert.Equal(t, "Hello, world!\n", string(output))
}

func outPipeTest(t *testing.T, cli *gosh.Client) {
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

func envTest(t *testing.T, cli *gosh.Client) {
	cmd, err := cli.Command("echo", "Hello, $TEST_ENV_NAME!")
	assert.NoError(t, err)
	err = cmd.Setenv([]string{"TEST_ENV_NAME=GSSH"})
	assert.NoError(t, err)
	output, err := cmd.Output()
	assert.NoError(t, err)

	assert.Equal(t, "Hello, GSSH!\n", string(output))
}

func TestMain(m *testing.M) {
	flag.StringVar(&addr, "addr", "", "The host of ssh")
	flag.StringVar(&user, "user", "root", "The username of client")
	flag.StringVar(&passwd, "pass", "", "The password of user")
	flag.StringVar(&key, "ssh-key", "", "The location of private key")

	flag.Parse()
	if addr != "" {
		os.Exit(m.Run())
	}
}
