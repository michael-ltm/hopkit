package sshmserverops

import (
	"os"
	"path/filepath"
	"regexp"
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

func TestCoreConditionalReferencesExist(t *testing.T) {
	core := readSkillFile(t, "SKILL.md")
	sectionStart := strings.Index(core, "## Conditional references")
	if sectionStart < 0 {
		t.Fatal("SKILL.md does not contain a Conditional references section")
	}

	linkPattern := regexp.MustCompile(`\[[^]]+\]\(([^)#?]+\.md)\)`)
	links := linkPattern.FindAllStringSubmatch(core[sectionStart:], -1)
	if len(links) < 4 {
		t.Fatalf("SKILL.md Conditional references contains %d documentation links; want at least 4", len(links))
	}

	seen := make(map[string]bool, len(links))
	for _, link := range links {
		reference := filepath.Clean(filepath.FromSlash(link[1]))
		if filepath.IsAbs(reference) || reference == ".." || strings.HasPrefix(reference, ".."+string(filepath.Separator)) {
			t.Errorf("conditional reference escapes the skill directory: %q", link[1])
			continue
		}
		if seen[reference] {
			t.Errorf("duplicate conditional reference %q", link[1])
			continue
		}
		seen[reference] = true
		if _, err := os.Stat(filepath.Join(skillDir(t), reference)); err != nil {
			t.Errorf("conditional reference %s: %v", link[1], err)
		}
	}
}

func requirePhrasesInOrder(t *testing.T, contents string, phrases ...string) {
	t.Helper()
	contents = strings.Join(strings.Fields(contents), " ")
	start := 0
	for _, phrase := range phrases {
		phrase = strings.Join(strings.Fields(phrase), " ")
		offset := strings.Index(contents[start:], phrase)
		if offset < 0 {
			t.Fatalf("missing ordered workflow phrase %q after byte %d", phrase, start)
		}
		start += offset + len(phrase)
	}
}

func TestProjectWorkflowPreservesVerifiedBuildContract(t *testing.T) {
	workflow := readSkillFile(t, "project-workflows.md")
	normalizedWorkflow := strings.Join(strings.Fields(workflow), " ")

	if count := strings.Count(workflow, "check_ssh"); count != 1 {
		t.Errorf("project workflow mentions check_ssh %d times; want exactly once", count)
	}
	requirePhrasesInOrder(t, workflow,
		"Resolve the profile once",
		"Run exactly one `check_ssh(mode=exec)`",
		"print the resolved workspace path",
		"verify expected project markers",
		"record the source revision or source archive SHA-256",
		"record the build start time",
		"pre-build artifact state and digest",
		"`verify_command` or the exact user-requested verification command",
		"pre-build verification only",
		"Run the configured `build_command`",
		"Validate the candidate artifact",
		"promote, copy, or move it to the canonical `artifact_path`",
		"modification time is after the recorded build start",
		"non-zero size",
		"SHA-256",
		"independent, side-effect-free artifact smoke command",
		"exact file under `local_artifact_dir`",
		"`artifact_path` basename",
	)

	for _, phrase := range []string{
		"non-detached `exec_project`",
		"`detach=false`",
		"from the outset",
		"realistic long `timeout_seconds` (or `0`)",
		"redirect stdout and stderr explicitly",
		"known log file under configured `remote_runs`",
		"`tail_logs platform=windows`",
		"transport or timeout",
		"PID",
		"process evidence",
		"Do not immediately relaunch",
	} {
		if !strings.Contains(normalizedWorkflow, phrase) {
			t.Errorf("project workflow does not contain Windows build contract phrase %q", phrase)
		}
	}

	lowerWorkflow := strings.ToLower(normalizedWorkflow)
	for _, forbidden := range []string{"fall back", "fallback"} {
		if strings.Contains(lowerWorkflow, forbidden) {
			t.Errorf("project workflow must not recommend detached-first fallback behavior containing %q", forbidden)
		}
	}
}
