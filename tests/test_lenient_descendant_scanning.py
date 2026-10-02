# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Finding, Severity, Skill, ThreatCategory
from skill_scanner.core.scanner import SkillScanner


class RecordingAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("recording")
        self.skills: list[Skill] = []

    def analyze(self, skill: Skill) -> list[Finding]:
        self.skills.append(skill)
        return []


@pytest.fixture
def recording_scanner():
    analyzer = RecordingAnalyzer()
    with SkillScanner(analyzers=[analyzer], cel_rules=[]) as scanner:
        yield scanner, analyzer


def write_skill(directory: Path, filename: str = "SKILL.md") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(
        f"---\nname: {directory.name}\ndescription: Formats local weather records.\nlicense: MIT\n---\n"
        "Read references/guide.md.\n"
    )


def write_markdown(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Guide\nReference: https://reference.example.invalid/guide\n")
    return path.resolve()


def symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")


def test_lenient_descendants_keep_file_coverage_without_cross_skill_findings(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    write_markdown(parent / "prompts" / "pipeline.md")
    write_markdown(parent / "resources" / "US" / "notes.md")
    expected_files = {p.resolve() for p in parent.rglob("*") if p.is_file()}

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True, check_overlap=True)

    assert {s.directory for s in analyzer.skills} == {
        parent,
        parent / "references",
        parent / "prompts",
        parent / "resources" / "US",
    }
    assert {f.path for f in analyzer.skills[0].files} == expected_files
    assert sum(f.path == guide for s in analyzer.skills for f in s.files) == 2
    assert len(report.scan_results) == 4
    assert not report.cross_skill_findings
    assert not report.skills_skipped


def test_lenient_keeps_independent_markdown_directory(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    write_markdown(parent / "references" / "guide.md")
    command = write_markdown(tmp_path / "commands" / "format.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, parent / "references", command.parent}
    assert command in {f.path for s in analyzer.skills for f in s.files}


def test_lenient_keeps_nested_manifest_skill(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    nested = parent / "nested"
    write_skill(parent)
    write_skill(nested)
    write_markdown(nested / "references" / "guide.md")

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True, check_overlap=True)

    assert {s.directory for s in analyzer.skills} == {parent, nested, nested / "references"}
    assert any(f.rule_id == "TRIGGER_OVERLAP_RISK" for f in report.cross_skill_findings)


def test_custom_manifest_keeps_nested_skills(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    nested = parent / "nested"
    write_skill(parent, "COMMAND.md")
    write_skill(nested, "COMMAND.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True, skill_file="COMMAND.md")

    assert {s.directory for s in analyzer.skills} == {parent, nested}


def test_lenient_keeps_markdown_outside_manifest_root(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    write_markdown(parent / "references" / "guide.md")
    changelog = write_markdown(tmp_path / "CHANGELOG.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, parent / "references", tmp_path}
    assert changelog in {f.path for s in analyzer.skills for f in s.files}


def test_rejected_parent_does_not_hide_markdown_descendant(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    (parent / "SKILL.md").write_bytes(b"\x00\xff\xfe")
    guide = write_markdown(parent / "references" / "guide.md")

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert [s.directory for s in analyzer.skills] == [guide.parent]
    assert guide in {f.path for s in analyzer.skills for f in s.files}
    assert any(item["skill"] == str(parent) for item in report.skills_skipped)


def test_uncovered_descendant_is_still_scanned(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    # The parent loader excludes .git contents; a nested candidate must not
    # be discarded solely because its resolved path is inside the parent.
    guide = write_markdown(parent / ".git" / "notes" / "guide.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, guide.parent}
    assert guide not in {f.path for f in analyzer.skills[0].files}
    assert guide in {f.path for s in analyzer.skills for f in s.files}


def test_failed_parent_analysis_does_not_hide_descendant(recording_scanner, tmp_path, monkeypatch):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    analyze = analyzer.analyze

    def fail_parent(skill):
        if skill.directory == parent:
            raise RuntimeError("parent analysis failed")
        return analyze(skill)

    monkeypatch.setattr(analyzer, "analyze", fail_parent)

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert any(item["skill"] == str(parent) for item in report.skills_skipped)
    assert [s.directory for s in analyzer.skills] == [guide.parent]


def test_parent_reporting_analyzer_failure_does_not_hide_descendant(recording_scanner, tmp_path, monkeypatch):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    scan = scanner._scan_single_skill

    def report_failure(skill, directory, **kwargs):
        result = scan(skill, directory, **kwargs)
        if directory == parent:
            result.analyzers_failed.append({"analyzer": "recording", "error": "incomplete analysis"})
        return result

    monkeypatch.setattr(scanner, "_scan_single_skill", report_failure)

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, guide.parent}


def test_external_markdown_symlink_is_still_scanned(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    scan_root = tmp_path / "scan"
    parent = scan_root / "weather"
    write_skill(parent)
    guide = write_markdown(tmp_path / "external" / "guide.md")
    symlink(parent / "linked-notes", guide.parent)

    scanner.scan_directory(scan_root, recursive=True, lenient=True)

    assert {s.directory.resolve() for s in analyzer.skills} == {parent, guide.parent}
    assert guide in {f.path for s in analyzer.skills for f in s.files}


def test_symlinked_manifest_and_cycle_keep_coverage(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    symlink(scan_root / "weather", parent)
    symlink(parent / "cycle", parent)

    scanner.scan_directory(scan_root, recursive=True, lenient=True)

    assert [s.directory.resolve() for s in analyzer.skills] == [parent]
    assert guide in {f.path for s in analyzer.skills for f in s.files}


@pytest.mark.parametrize("markdown_count", [1, 2])
@pytest.mark.parametrize("check_overlap", [False, True])
def test_static_body_check_receives_synthetic_descendant(tmp_path, monkeypatch, markdown_count, check_overlap):
    """Loaded files do not substitute for the static check's body input."""
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = parent / "references" / "guide.md"
    write_markdown(guide)
    guide.write_text("# Guide\nUse metric units for the local temperature table.\n")
    if markdown_count == 2:
        write_markdown(parent / "references" / "notes.md")

    from skill_scanner.core.analyzers import static as static_module

    original = static_module.check_active_remote_execution
    observed = {}

    def observe_body(skill):
        observed[skill.directory] = skill.instruction_body
        return original(skill)

    monkeypatch.setattr(static_module, "check_active_remote_execution", observe_body)
    with SkillScanner(analyzers=[StaticAnalyzer()], cel_rules=[]) as scanner:
        child = scanner.loader.load_skill(guide.parent, lenient=True)
        report = scanner.scan_directory(tmp_path, recursive=True, lenient=True, check_overlap=check_overlap)

    assert "Use metric units" not in observed[parent]
    assert observed[guide.parent] == child.instruction_body
    assert len(report.scan_results) == 2
    assert not report.cross_skill_findings


def test_body_only_custom_analyzer_keeps_its_finding(tmp_path):
    """A benign marker demonstrates the contract without executing a payload."""
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    guide.write_text("# Guide\nUse metric units for the local temperature table.\n")

    class BodyMarkerAnalyzer(BaseAnalyzer):
        def __init__(self):
            super().__init__("body_marker")

        def analyze(self, skill):
            if "Use metric units" not in skill.instruction_body:
                return []
            return [
                Finding(
                    id="body-marker",
                    rule_id="LOCAL_BODY_MARKER",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    severity=Severity.INFO,
                    title="Benign body marker observed",
                    description="Records receipt of a harmless unit-test input.",
                    file_path=skill.skill_md_path.name,
                    analyzer=self.get_name(),
                )
            ]

    with SkillScanner(analyzers=[BodyMarkerAnalyzer()], cel_rules=[]) as scanner:
        report = scanner.scan_directory(tmp_path, recursive=True, lenient=True, check_overlap=True)

    assert len(report.scan_results) == 2
    assert [f.rule_id for r in report.scan_results for f in r.findings] == ["LOCAL_BODY_MARKER"]
    assert not report.cross_skill_findings
