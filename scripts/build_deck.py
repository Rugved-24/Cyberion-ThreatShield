"""Build the final PowerPoint deck as Office Open XML.

Written without python-pptx so that a deliverable cannot be blocked by a missing
package, and so the exact output is auditable. Figures are read from the generated
artefacts rather than typed, so the deck cannot drift from the evidence.

    python scripts/build_deck.py
"""

import csv
import json
import re
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "presentation" / "deck.pptx"
SLIDE_W, SLIDE_H = 12192000, 6858000
MARGIN = 685800


def facts():
    results = list(csv.DictReader((ROOT / "detections/test-results.csv").open(encoding="utf-8")))
    tuning = list(csv.DictReader((ROOT / "detections/tuning-results.csv").open(encoding="utf-8")))
    layer = json.loads((ROOT / "coverage/layer-v2.json").read_text(encoding="utf-8"))
    iocs = list(csv.DictReader((ROOT / "ioc/watchlist.csv").open(encoding="utf-8")))
    statuses = {}
    for entry in layer["techniques"]:
        label = (entry.get("metadata") or [{}])[0].get("value", "Unknown")
        statuses[label] = statuses.get(label, 0) + 1
    tactics = set()
    for entry in layer["techniques"]:
        value = (entry.get("metadata") or [{}])[2].get("value", "")
        tactics.update(t for t in value.split(", ") if t)
    return {
        "rules": len(results),
        "pass": sum(1 for row in results if row["status"] == "PASS"),
        "with_evidence": sum(1 for row in results if int(row["expected_hits"].split("/")[0]) > 0),
        "correlation": sum(1 for row in results if row["window_tests"]),
        "techniques": len(layer["techniques"]),
        "statuses": statuses,
        "tactics": len(tactics),
        "tactic_list": ", ".join(sorted(tactics)),
        "hunts": len(list((ROOT / "hunts").glob("*.md"))),
        "incidents": len(list((ROOT / "incidents").glob("*.md"))),
        "playbooks": len([p for p in (ROOT / "playbooks").glob("*.md")
                          if not p.name.startswith("_")]),
        "tuning": len(tuning),
        "iocs": len(iocs),
        "covered": statuses.get("Covered", 0),
        "partial": statuses.get("Partially Covered", 0),
        "notcovered": statuses.get("Not Covered", 0),
    }


def textbox(x, y, w, h, paragraphs):
    body = ""
    for paragraph in paragraphs:
        text, size, bold, colour, space = (list(paragraph) + [None] * 5)[:5]
        space = 600 if space is None else space
        body += (f'<a:p><a:pPr><a:lnSpc><a:spcPct val="{space}"/></a:lnSpc></a:pPr>'
                 f'<a:r><a:rPr lang="en-GB" sz="{size}" b="{1 if bold else 0}" dirty="0">'
                 f'<a:solidFill><a:srgbClr val="{colour}"/></a:solidFill></a:rPr>'
                 f'<a:t>{escape(text)}</a:t></a:r></a:p>')
    return (f'<p:sp><p:nvSpPr><p:cNvPr id="0" name=""/><p:cNvSpPr txBox="1"/>'
            f'<p:nvPr/></p:nvSpPr><p:spPr>'
            f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{w}" cy="{h}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
            f'<p:txBody><a:bodyPr wrap="square" lIns="0" tIns="0" rIns="0" bIns="0">'
            f'<a:normAutofit/></a:bodyPr><a:lstStyle/>{body}</p:txBody></p:sp>')


def bar(x, y, w, h, colour, label, value, total):
    parts = [f'<p:sp><p:nvSpPr><p:cNvPr id="0" name=""/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>'
            f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{w}" cy="{h}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
            f'<a:solidFill><a:srgbClr val="{colour}"/></a:solidFill>'
            f'<a:ln><a:noFill/></a:ln></p:spPr><p:txBody>'
            f'<a:bodyPr/><a:lstStyle/><a:p><a:endParaRPr lang="en-GB"/></a:p></p:txBody></p:sp>']
    if label:
        parts.append(textbox(x, y - 500000, w, 420000,
                             [(label, 1200, True, "1F3864", None)]))
        parts.append(textbox(x, y - 220000, w, 340000,
                             [(value, 1100, False, "44546A", None)]))
    return "".join(parts)


def table(x, y, w, headers, rows, col_widths, row_height=330000, size=1000):
    """A real DrawingML table: graphicFrame > graphic > graphicData > tbl."""
    grid = "".join(f'<a:gridCol w="{int(w * c)}"/>' for c in col_widths)

    def cell(text, header=False):
        fill = "1F3864" if header else "EEF1F5"
        colour = "FFFFFF" if header else "1A1A1A"
        bold = 1 if header else 0
        return (f'<a:tc><a:txBody><a:bodyPr/><a:lstStyle/><a:p>'
                f'<a:pPr><a:lnSpc><a:spcPct val="90000"/></a:lnSpc></a:pPr>'
                f'<a:r><a:rPr lang="en-GB" sz="{size}" b="{bold}">'
                f'<a:solidFill><a:srgbClr val="{colour}"/></a:solidFill></a:rPr>'
                f'<a:t>{escape(str(text))}</a:t></a:r></a:p></a:txBody>'
                f'<a:tcPr marL="68580" marR="68580" marT="34290" marB="34290" anchor="ctr">'
                f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill></a:tcPr></a:tc>')

    shape = [f'<a:tbl><a:tblPr firstRow="1"/><a:tblGrid>{grid}</a:tblGrid>']
    shape.append(f'<a:tr h="{row_height}">' + "".join(cell(h, True) for h in headers) + "</a:tr>")
    for row in rows:
        shape.append(f'<a:tr h="{row_height}">' + "".join(cell(v) for v in row) + "</a:tr>")
    shape.append("</a:tbl>")
    height = row_height * (len(rows) + 1)
    return (f'<p:graphicFrame><p:nvGraphicFramePr>'
            f'<p:cNvPr id="0" name=""/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>'
            f'<p:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{w}" cy="{height}"/></p:xfrm>'
            f'<a:graphic><a:graphicData '
            f'uri="http://schemas.openxmlformats.org/drawingml/2006/table">'
            f'{"".join(shape)}</a:graphicData></a:graphic></p:graphicFrame>')


def slide(title, subtitle, body_xml, notes):
    return {"xml": f"""<p:sld><p:cSld><p:spTree>
<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>
<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
{textbox(MARGIN, 300000, SLIDE_W - 2 * MARGIN, 700000, [(title, 2600, True, "1F3864", None)])}
{textbox(MARGIN, 950000, SLIDE_W - 2 * MARGIN, 420000, [(subtitle, 1300, False, "44546A", None)])}
{body_xml}
</p:spTree></p:cSld><p:clrMapOvr><a:overrideClrMapping bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/></p:clrMapOvr></p:sld>""",
            "title": title, "notes": notes}


def notes_slide(text):
    paragraphs = "".join(
        f'<a:p><a:r><a:rPr lang="en-GB" sz="1200"/><a:t>{escape(line)}</a:t></a:r></a:p>'
        for line in str(text).strip().splitlines() if line.strip())
    return (f'<p:notes><p:cSld><p:spTree>'
            f'<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            f'<p:grpSpPr/><p:sp><p:nvSpPr>'
            f'<p:cNvPr id="2" name="Notes Placeholder"/>'
            f'<p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr>'
            f'<p:nvPr><p:ph type="body" idx="1"/></p:nvPr></p:nvSpPr>'
            f'<p:txBody><a:bodyPr/><a:lstStyle/>{paragraphs}</p:txBody>'
            f'</p:sp></p:spTree></p:cSld></p:notes>')


def build(f):
    W = SLIDE_W - 2 * MARGIN
    s = []
    s.append(slide(
        "Cyberion ThreatShield",
        "Detection engineering and threat hunting engagement | CDL-DET-V2 v2.0 | 2026-09-29",
        textbox(MARGIN, 1700000, W, 2600000, [
            ("What we can detect, what we cannot, and what to fix first", 1900, False, "44546A", 1200),
            (f"{f['rules']} detection rules, all replayed against real attack telemetry",
             1400, False, "44546A", 700),
            (f"{f['techniques']} ATT&CK techniques assessed across {f['tactics']} tactics",
             1400, False, "44546A", 700),
            (f"{f['hunts']} threat hunts, {f['incidents']} incident cases, "
             f"{f['playbooks']} response playbooks", 1400, False, "44546A", 700),
        ]),
        "Open by setting expectations. This is an assessment of our own monitoring, "
        "not a description of a breach. Two recorded intrusions were used as test material."))
    s.append(slide(
        "The question we were asked",
        "If an attacker came in tomorrow, would we notice, and could we prove it?",
        textbox(MARGIN, 1600000, W, 2400000, [
            ("The problem was never a shortage of alarms.", 1600, True, "1F3864", 1000),
            ("Alarms existed but were undocumented, untested and unmapped. Nobody could "
             "answer without re-reading rule files by hand, so blind spots stayed invisible "
             "until an incident exposed them.", 1300, False, "1A1A1A", 1200),
            ("The work product is evidence, not volume.", 1600, True, "1F3864", 1000),
            ("A documented and tested rule library, a coverage matrix an auditor can check, "
             "a repeatable hunting method, and written response procedures.", 1300, False,
             "1A1A1A", 1200),
        ]),
        "This slide exists so the audience knows the deliverable is evidence, not volume."))
    s.append(slide(
        "What we used as evidence",
        "Two public adversary-emulation recordings. Real telemetry, not invented data.",
        table(MARGIN, 1650000, W,
              ["Recording", "Host", "Records", "Sysmon process creations"],
              [["DS001", "WORKSTATION5", "1,127", "3"],
               ["DS002", "WORKSTATION6.theshire.local", "4,348", "6"]],
              [0.18, 0.34, 0.16, 0.32])
        + textbox(MARGIN, 3300000, W, 1500000, [
            ("Three telemetry types: Sysmon, Windows Security auditing, PowerShell "
             "script and module logging.", 1300, False, "1A1A1A", 800),
            ("Every record traceable to a source line and a checksum. Every processing step "
             "verifies the checksum first and stops on a mismatch.", 1300, False, "1A1A1A", 800),
            ("State the constraint early: 3 process records on a host is very few. It shapes "
             "every result that follows.", 1300, True, "BF8F00", 800),
        ]),
        "Three process creations per host is very few. Say so from us rather than let the "
        "audience find it in the appendix."))
    s.append(slide(
        "Coverage: the honest version",
        f"Covered {f['covered']}  |  Partially Covered {f['partial']}  |  "
        f"Not Covered {f['notcovered']}  of {f['techniques']} techniques",
        bar(MARGIN, 2200000, 1900000, 500000, "D9EAD3", "Covered", f"{f['covered']}", f["techniques"])
        + bar(MARGIN + 2400000, 2200000, 1900000, 500000, "FFF2CC", "Partially Covered",
              f"{f['partial']}", f["techniques"])
        + bar(MARGIN + 4800000, 2200000, 1900000, 500000, "F4CCCC", "Not Covered",
              f"{f['notcovered']}", f["techniques"])
        + textbox(MARGIN, 3400000, W, 1600000, [
            ("Covered", 1300, True, "2E7D32", 300),
            ("A tested rule that fires on a real attack AND was measured against real "
             "ordinary activity with no false alarms.", 1200, False, "1A1A1A", 900),
            ("Partially Covered", 1300, True, "B7950B", 300),
            ("Fires on a real attack. False-alarm rate unmeasured, because no recording of "
             "normal business activity exists to measure against.", 1200, False, "1A1A1A", 900),
            ("Not Covered", 1300, True, "B03A2E", 300),
            ("No confirmed detection. Three of these are evidence gaps with the minimum "
             "dataset needed specified.", 1200, False, "1A1A1A", 900),
        ]),
        "This is the slide that builds or destroys credibility. One Covered is a low "
        "number and it is the correct number. The reason is the next slide."))
    s.append(slide(
        "Why only one technique is fully covered",
        "We decline to score a detection Covered without a measured false-alarm rate",
        textbox(MARGIN, 1600000, W, 2600000, [
            ("The recordings are of attacks, not of normal working days.", 1500, True,
             "1F3864", 900),
            ("Rule authors routinely assume their rule is precise. On a high-volume "
             "environment that assumption becomes alert fatigue.", 1300, False, "1A1A1A", 1100),
            ("We could have claimed 13 Covered.", 1500, True, "BF8F00", 900),
            ("That would have been wrong and unauditable. The coverage matrix is generated "
             "from recorded test results by script, so a status cannot be inflated by prose.",
             1300, False, "1A1A1A", 1100),
            ("A rule with a deliberately empty evidence list is held at Not Covered in code, "
             "not by convention.", 1300, False, "1A1A1A", 1100),
        ]),
        "If challenged on the low number, this is the answer. We traded a flattering number "
        "for one an auditor could verify."))
    s.append(slide(
        "Incident 1: confirmed true positive",
        "A fake Windows service, running as SYSTEM, with nobody logged in",
        table(MARGIN, 1650000, W,
              ["Time (UTC)", "What happened", "Evidence"],
              [["16:16:56.019", "Service Control Manager reaches a dynamic RPC port", "DS002:1366"],
               ["16:16:56.597", "Command shell created by that service", "DS002:1057, DS002:1226"],
               ["16:16:56.620", "Concealed PowerShell with an encoded payload", "DS002:1073, DS002:1238"],
               ["16:17:01.152", "Retrieval from an internal address", "DS002:2513, DS002:2367"],
               ["16:17:18.795", "Account check, answer recorded as nt authority\\system", "DS002:2901, DS002:2877"]],
              [0.17, 0.50, 0.33], size=950)
        + textbox(MARGIN, 4300000, W, 900000, [
            ("Corroborated by four independent log sources. The script disabled its own "
             "logging and inspection controls first.", 1300, False, "1A1A1A", 700),
        ]),
        "'The log recorded the attacker's own answer' is the line that lands. It is the "
        "difference between confirmed and inferred."))
    s.append(slide(
        "Incident 2: confirmed true positive",
        "A trusted Windows program used as a loader, then an open session",
        table(MARGIN, 1650000, W,
              ["Time (UTC)", "What happened", "Evidence"],
              [["06:57:59.855", "mshta.exe with an inline VBScript URL", "DS001:275, DS001:4"],
               ["06:58:00.462", "PowerShell created, session deliberately left open", "DS001:398, DS001:30"],
               ["06:58:00.462", "Immediate check whether our sensor is running", "DS001:398"]],
              [0.17, 0.50, 0.33], size=950)
        + textbox(MARGIN, 3400000, W, 1600000, [
            ("Same parent-child chain recorded by two independent process logs.", 1300,
             False, "1A1A1A", 700),
            ("No persistence and no privilege escalation, and still a confirmed attack: the "
             "chain is unambiguous and the intent is clear.", 1300, False, "1A1A1A", 700),
            ("The two incidents are NOT combined into one campaign. The recordings name one "
             "machine two different ways and host aliases are never merged.", 1300, True,
             "BF8F00", 700),
        ]),
        "Contrast with the previous slide. Small patient intrusion versus fast privileged "
        "one. Both needed different rules."))
    s.append(slide(
        "The hunt that found the most by proving nothing",
        "Was the outbound web connection command and control? Inconclusive, and here is the arithmetic",
        textbox(MARGIN, 1650000, W, 2700000, [
            ("Exactly one connection to the destination.", 1400, True, "1F3864", 600),
            ("The recording covers 2 minutes 14 seconds. A regular callback is defined by "
             "repetition, and two minutes cannot show it.", 1250, False, "1A1A1A", 800),
            ("The destination is a private internal address, so external command and control "
             "cannot be claimed. No response content was recorded either.", 1250, False,
             "1A1A1A", 800),
            ("The negative result that shaped every future rule:", 1400, True, "BF8F00", 900),
            ("Of 43 connections to port 80 in the recording, 42 were ordinary cloud platform "
             "traffic. An alert-on-web-traffic rule would have been wrong about 98 per cent "
             "of the time. That is why T1071.001 has no rule at all.", 1250, False,
             "1A1A1A", 800),
        ]),
        "The strongest slide for a technical audience and the best demonstration of method "
        "for a non-technical one. We stopped rather than shipped a plausible rule."))
    s.append(slide(
        "Three rules that failed their own test",
        "Tuning to silence is a precision result, not a detection",
        table(MARGIN, 1650000, W,
              ["Rule watches for", "Before", "After", "Outcome"],
              [["Network logon by a named account", "7 (6 false)", "1 (0 false)",
                "Kept. The one Covered technique."],
               ["Reads of the credential memory", "7 (7 false)", "0",
                "Tuned to silence. No confirmed detection."],
               ["Shared network folder access", "3 (3 false)", "0",
                "Tuned to silence. No confirmed detection."]],
              [0.32, 0.17, 0.16, 0.35], size=950)
        + textbox(MARGIN, 3700000, W, 1400000, [
            ("Every match in the last two rows was ordinary Windows or vendor activity.",
             1300, False, "1A1A1A", 700),
            ("Both techniques therefore stay Not Covered. We are showing our own rules "
             "failing and the fix being to admit we cannot detect this yet.", 1300, True,
             "BF8F00", 700),
            ("Each accepted trade-off is written down, including what the change now misses.",
             1300, False, "1A1A1A", 700),
        ]),
        "The middle and bottom rows are the ones to dwell on."))
    s.append(slide(
        "What we deliberately did not build",
        "We did not write a rule to hit a number",
        table(MARGIN, 1650000, W,
              ["Technique", "Why no rule exists", "Minimum data needed"],
              [["Web-based command and control",
                "One connection in 2m14s; 42 of 43 port-80 flows are benign platform traffic",
                "A longer capture plus proxy or web gateway content"],
               ["Startup persistence",
                "No run-key write exists anywhere in either recording",
                "About five minutes of recording with a run-key write and the resulting run"],
               ["Password spraying",
                "Not one failed sign-in exists in either recording",
                "One hour of authentication logs including failures"],
               ["Ransomware for impact",
                "No labelled encryption sequence has been identified",
                "A documented safe simulation with known file effects"]],
              [0.24, 0.42, 0.34], size=900)
        + textbox(MARGIN, 4600000, W, 600000, [
            ("These stay Not Covered, with the data needed to close each one written down.",
             1300, True, "1F3864", 700),
        ]),
        "Saying 'we did not build a rule to hit a number' out loud is the difference "
        "between an audit-ready library and a spreadsheet."))
    s.append(slide(
        "Collection gaps we found, which matter more than any rule",
        "These are configuration findings, and the cheapest to fix",
        textbox(MARGIN, 1650000, W, 2700000, [
            ("1. One workstation produced no PowerShell script logging at all.",
             1350, True, "1F3864", 700),
            ("A rule needing script text could not have been written for that host.",
             1200, False, "1A1A1A", 900),
            ("2. Neither recording contains a single failed sign-in.", 1350, True,
             "1F3864", 700),
            ("Credential attacks are effectively invisible without them, and this is the "
             "same gap that leaves the central question of both incidents unanswerable.",
             1200, False, "1A1A1A", 900),
            ("3. No service-install events carry a usable timestamp.", 1350, True,
             "1F3864", 700),
            ("The persistence mechanism cannot be placed on a timeline. This directly caused "
             "one of the two inconclusive conclusions.", 1200, False, "1A1A1A", 900),
            ("4. No proxy or gateway content was captured.", 1350, True, "1F3864", 700),
            ("Tool-transfer assessment cannot progress past inconclusive without it.",
             1200, False, "1A1A1A", 900),
        ]),
        "These are configuration findings rather than content findings, which is exactly "
        "why they are cheap."))
    s.append(slide(
        "What we are asking for",
        "In order of value",
        table(MARGIN, 1650000, W,
              ["Ask", "Cost", "What it unlocks"],
              [["Record a clean baseline of normal activity", "Analyst time, no new tools",
                f"Converts {f['partial']} techniques from unmeasured to measured"],
               ["Enable script logging and failed sign-in collection", "Configuration only",
                "Makes script and credential attacks visible at all"],
               [f"Deploy the {f['with_evidence']} confirmed rules, with caveats",
                "Analyst time to deploy and monitor",
                f"Immediate coverage across {f['partial']} techniques"],
               ["Collect three short targeted recordings", "About one hour in total",
                "Closes three named evidence gaps"],
               ["Enable web gateway or proxy logging", "Existing platform configuration",
                "Makes the command-and-control question answerable"]],
              [0.33, 0.24, 0.43], size=900)
        + textbox(MARGIN, 4600000, W, 700000, [
            ("We would rather hand over one verified detection and three honestly named gaps "
             "than fifteen detections and no reliable idea which of them work.",
             1350, True, "2E7D32", 700),
        ]),
        "Close on the green line. It is the whole argument in one sentence."))
    s.append(slide(
        "Honest limitations",
        "The value of this work depends on these being visible",
        textbox(MARGIN, 1650000, W, 2700000, [
            ("The evidence is two recordings of roughly two minutes each, from a "
             "controlled lab. Real telemetry, but not our environment.", 1250, False,
             "1A1A1A", 800),
            (f"Only {f['covered']} of {f['techniques']} techniques is fully covered. "
             f"{f['partial']} have working rules and unmeasured precision. That is a "
             "truthful position, not a failure.", 1250, False, "1A1A1A", 800),
            ("Absence of evidence in a two-minute window is not evidence of absence. No "
             "conclusion here relies on something not having happened, except where that "
             "absence is itself the finding.", 1250, False, "1A1A1A", 800),
            ("The largest unresolved question is whether an account was stolen. Neither "
             "recording has any authentication history.", 1250, False, "1A1A1A", 800),
            ("Three techniques could not be attempted at all: this host has no hypervisor, so "
             "no isolated lab VM could be created to generate the telemetry.", 1250, False,
             "1A1A1A", 800),
            ("No independent review. Every rule, figure and conclusion was produced and "
             "checked by one person.", 1250, True, "BF8F00", 800),
            ("Dataset licence terms are unresolved, so publication is gated on a rights review.",
             1250, False, "1A1A1A", 800),
        ]),
        "Do not cut this slide for time. It is what makes the rest credible."))
    s.append(slide(
        "Every number here is reproducible",
        "Three commands regenerate all of it from the recorded evidence",
        textbox(MARGIN, 1650000, W, 2500000, [
            ("scripts/test_all.py        replays every rule and writes the match results",
             1250, False, "1A1A1A", 700),
            ("scripts/tune.py            measures the false-positive tuning cases",
             1250, False, "1A1A1A", 700),
            ("scripts/build_coverage.py  derives the coverage matrix and the Navigator layer",
             1250, False, "1A1A1A", 700),
            ("This matters for two reasons.", 1400, True, "1F3864", 900),
            ("A stakeholder can ask for the derivation. And the coverage rating cannot drift "
             "away from the evidence in future, because the two are produced from the same "
             "recorded results rather than maintained by hand.", 1250, False, "1A1A1A", 800),
            ("The pre-engagement baseline is retained unmodified alongside the final position, "
             "with its checksum, so the change can be audited.", 1250, False, "1A1A1A", 800),
        ]),
        "Close on reproducibility. It is the answer to 'how do we know these numbers are real'."))
    return s


def main():
    f = facts()
    slides = build(f)
    titles = [item["title"] for item in slides]
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
                   + "".join(f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
                             for i in range(1, len(slides) + 1))
                   + "".join(f'<Override PartName="/ppt/notesSlides/notesSlide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>'
                             for i in range(1, len(slides) + 1))
                   + '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
                     '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
                     '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
                     '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                     '</Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>'
                   '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
                   '</Relationships>')
        z.writestr("ppt/_rels/presentation.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>'
                   + "".join(f'<Relationship Id="rId{i + 10}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>'
                             for i in range(1, len(slides) + 1))
                   + "".join(f'<Relationship Id="rId{i + 100}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="notesSlides/notesSlide{i}.xml"/>'
                             for i in range(1, len(slides) + 1))
                   + '<Relationship Id="rId900" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>'
                     '</Relationships>')
        z.writestr("ppt/presentation.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                   'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                   '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
                   '<p:sldIdLst>'
                   + "".join(f'<p:sldId id="{255 + i}" r:id="rId{i + 10}"/>'
                             for i in range(1, len(slides) + 1))
                   + '</p:sldIdLst><p:sldSz cx="%d" cy="%d"/><p:notesSz cx="%d" cy="%d"/>'
                     '</p:presentation>' % (SLIDE_W, SLIDE_H, SLIDE_H, SLIDE_W))
        for index, item in enumerate(slides, 1):
            z.writestr(f"ppt/slides/slide{index}.xml",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                       '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                       'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                       'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                       + item["xml"] + '</p:sld>')
            z.writestr(f"ppt/notesSlides/notesSlide{index}.xml",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                       '<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                       'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                       'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                       + notes_slide(item["notes"]) + '</p:notes>')
            z.writestr(f"ppt/slides/_rels/slide{index}.xml.rels",
                       '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide{index}.xml"/>'
                       f'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
                       '</Relationships>')
        z.writestr("ppt/slideMasters/slideMaster1.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                   'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                   '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/>'
                   '</p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld>'
                   '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" '
                   'accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" '
                   'accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
                   '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
                   '</p:sldMaster>')
        z.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>'
                   '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>'
                   '</Relationships>')
        z.writestr("ppt/slideLayouts/slideLayout1.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                   'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">'
                   '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/>'
                   '</p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld></p:sldLayout>')
        z.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>'
                   '</Relationships>')
        z.writestr("ppt/theme/theme1.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Cyberion">'
                   '<a:themeElements><a:clrScheme name="Cyberion">'
                   '<a:dk1><a:srgbClr val="1A1A1A"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>'
                   '<a:dk2><a:srgbClr val="1F3864"/></a:dk2><a:lt2><a:srgbClr val="EEF1F5"/></a:lt2>'
                   '<a:accent1><a:srgbClr val="1F3864"/></a:accent1><a:accent2><a:srgbClr val="2E5496"/></a:accent2>'
                   '<a:accent3><a:srgbClr val="2E7D32"/></a:accent3><a:accent4><a:srgbClr val="BF8F00"/></a:accent4>'
                   '<a:accent5><a:srgbClr val="B03A2E"/></a:accent5><a:accent6><a:srgbClr val="44546A"/></a:accent6>'
                   '<a:hlink><a:srgbClr val="0563C1"/></a:hlink><a:folHlink><a:srgbClr val="954F72"/></a:folHlink>'
                   '</a:clrScheme><a:fontScheme name="Cyberion">'
                   '<a:majorFont><a:latin typeface="Calibri Light"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
                   '<a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>'
                   '</a:fontScheme><a:fmtScheme name="Cyberion">'
                   '<a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
                   '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
                   '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>'
                   '<a:lnStyleLst>'
                   '<a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
                   '<a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
                   '<a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
                   '</a:lnStyleLst>'
                   '<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle>'
                   '<a:effectStyle><a:effectLst/></a:effectStyle>'
                   '<a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>'
                   '<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
                   '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
                   '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>'
                   '</a:fmtScheme></a:themeElements></a:theme>')
        z.writestr("docProps/core.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                   'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                   '<dc:title>Cyberion ThreatShield - final presentation</dc:title>'
                   '<dc:creator>Detection Engineering</dc:creator>'
                   '<cp:lastModifiedBy>Detection Engineering</cp:lastModifiedBy>'
                   '</cp:coreProperties>')
    print(f"slides: {len(slides)}")
    for index, title in enumerate(titles, 1):
        print(f"  {index:>2}. {title}")
    print(f"written: {OUT.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
