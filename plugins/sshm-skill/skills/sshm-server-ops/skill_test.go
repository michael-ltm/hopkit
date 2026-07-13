package sshmserverops

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func skillDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate skill_test.go")
	}
	return filepath.Dir(filename)
}

func readSkillFile(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(skillDir(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(contents)
}

func TestCoreSkillBudget(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	if words := len(strings.Fields(core)); words > 500 {
		t.Fatalf("SKILL.md has %d words; want at most 500", words)
	}
}

func TestCoreSkillRequiredGuidance(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	for _, phrase := range []string{
		"list_projects",
		"get_project",
		"upsert_project",
		"exec_project",
		"do not retry the same failed mutation blindly",
		"changed host key",
	} {
		if !strings.Contains(core, phrase) {
			t.Errorf("SKILL.md does not contain %q", phrase)
		}
	}
}

func TestSkillReferencesExist(t *testing.T) {
	for _, name := range []string{
		"project-workflows.md",
		"onboarding.md",
		"quick-reference.md",
		"ai-patterns.md",
	} {
		if _, err := os.Stat(filepath.Join(skillDir(t), name)); err != nil {
			t.Errorf("required reference %s: %v", name, err)
		}
	}
}
