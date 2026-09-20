//go:build with_ebpf && (linux || android)

package singebpf

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestLibraryBoundary prevents the kernel mechanism package from acquiring a
// dependency on application code from the original source repository. The
// complete source tree is checked, including tests and nested tools.
func TestLibraryBoundary(t *testing.T) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate eBPF package source")
	}
	packageDirectory := filepath.Dir(currentFile)
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(packageDirectory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		name, relativeErr := filepath.Rel(packageDirectory, path)
		if relativeErr != nil {
			return relativeErr
		}
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Errorf("parse %s: %v", name, parseErr)
			return nil
		}
		for _, importSpec := range parsed.Imports {
			importPath, unquoteErr := strconv.Unquote(importSpec.Path.Value)
			if unquoteErr != nil {
				t.Errorf("parse import in %s: %v", name, unquoteErr)
				continue
			}
			if importPath == "github.com/sagernet/sing-box" ||
				strings.HasPrefix(importPath, "github.com/sagernet/sing-box/") ||
				importPath == "github.com/sagernet/sing-tun" ||
				strings.HasPrefix(importPath, "github.com/sagernet/sing-tun/") {
				t.Errorf("%s imports forbidden application package %q", name, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicResourceTypesDoNotExposeRawKernelHandles(t *testing.T) {
	resourceTypes := []struct {
		name  string
		value any
	}{
		{name: "SelfBypass", value: (*SelfBypass)(nil)},
		{name: "TCBackend", value: (*TCBackend)(nil)},
		{name: "SharedPacketRewriteBackend", value: (*SharedPacketRewriteBackend)(nil)},
	}
	forbiddenMethods := []string{
		"UpdateSelector",
		"SetSelector",
		"UpdateDNSMode",
		"UpdateFakeIPPolicy",
		"UpdateRuleSet",
		"Map",
		"LocalEgressProgram",
		"LocalEgressProgramFD",
		"SharedIngressProgram",
		"SharedIngressProgramFD",
		"DeliveryIngressProgramFD",
		"IngressProgram",
		"IngressProgramFD",
		"EgressProgram",
		"EgressProgramFD",
		"ICMPEchoLocalReplyProgram",
		"ICMPEchoLocalReplyProgramFD",
		"ICMPEchoSharedReplyProgram",
		"ICMPEchoSharedReplyProgramFD",
	}
	for _, resourceType := range resourceTypes {
		typeOf := reflect.TypeOf(resourceType.value)
		for _, methodName := range forbiddenMethods {
			if _, loaded := typeOf.MethodByName(methodName); loaded {
				t.Errorf("%s exposes raw kernel handle accessor %s", resourceType.name, methodName)
			}
		}
	}
}

func TestZeroTCBackendPolicyUpdateReturnsError(t *testing.T) {
	backend := new(TCBackend)
	if _, err := backend.UpdateLocalDestinationDecisions(nil); err == nil {
		t.Fatal("zero TC backend policy update unexpectedly succeeded")
	}
}
