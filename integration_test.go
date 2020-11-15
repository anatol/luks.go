package luks

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
)

func TestBootInQemu(t *testing.T) {
	cmd := exec.Command("go", "test", "-c", "examples/end2end_test.go", "-o", "luks_end2end_test")
	if testing.Verbose() {
		log.Print("compile in-qemu test binary")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("luks_end2end_test")

	// These integration tests use QEMU with a statically-compiled kernel (to avoid inintramfs) and a specially
	// prepared rootfs. See [instructions](https://github.com/anatol/vmtest/blob/master/docs/prepare_image.md)
	// how to prepare these binaries.
	params := []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic", "-m", "8G", "-smp", strconv.Itoa(runtime.NumCPU())}
	if os.Getenv("TEST_DISABLE_KVM") != "1" {
		params = append(params, "-enable-kvm", "-cpu", "host")
	}
	opts := vmtest.QemuOptions{
		OperatingSystem: vmtest.OS_LINUX,
		Kernel:          "bzImage",
		Params:          params,
		Disks:           []string{"rootfs.cow"},
		Append:          []string{"root=/dev/sda", "rw"},
		Verbose:         testing.Verbose(),
		Timeout:         50 * time.Second,
	}
	// Run QEMU instance
	qemu, err := vmtest.NewQemu(&opts)
	if err != nil {
		t.Fatal(err)
	}
	// Stop QEMU at the end of the test case
	defer qemu.Stop()

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", "localhost:10022", config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	scpSess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	if err := scp.CopyPath("luks_end2end_test", "luks_end2end_test", scpSess); err != nil {
		t.Error(err)
	}

	testCmd := "./luks_end2end_test -test.parallel " + strconv.Itoa(runtime.NumCPU())
	if testing.Verbose() {
		testCmd += " -test.v"
	}

	output, err := sess.CombinedOutput(testCmd)
	if testing.Verbose() {
		fmt.Print(string(output))
	}
	if err != nil {
		t.Fatal(err)
	}
}
