# Instructions for Claude — HERO FILE EXTRACTOR

The owner works **only from a phone** (no computer) and writes Arabic. Reply in Arabic. Be honest: never say something was
extracted/fixed unless you ran the tool and read its report.

## Workflow when given this repo URL + a task
1. `git clone --depth 1 <repo>` (public repos only; for large release assets use `curl -L` on the release URL).
2. `pip install -r requirements.txt` and, for RAR, `apt-get install -y unrar` (if unavailable, say RAR may fail).
3. Inspect first when the task is vague: `python -m hero_extract <inputs> -o /tmp/out --list-only`, then read `/tmp/out/REPORT.md`.
4. Run the real extraction with filters, output to `/mnt/user-data/outputs/results` (or zip it) and present the files.
5. Report counts from `REPORT.md`/`report.json`: extracted, corrupt (`_needs_review/`), unsupported, encrypted, `originals_unchanged`.
   Mention anything in `problems`. Never hide failures.

## Turning a request into flags
- Format filter: `--type glb` (extensions, comma list). Broad kinds: `--category models3d,images,audio,video,documents`.
- Subject filter: `--match "label=term1|term2,label2=termA|termB"` — the label becomes the output folder.
  Matching is whole-word on path tokens and (for GLB/GLTF/OBJ/DAE) internal node/mesh/material names; `street` does NOT match `tree`.
  Expand Arabic requests into English synonyms yourself, and tell the user which terms you used:
  - الأشجار: `trees=tree|pine|palm|oak|birch|spruce|cedar|willow|bush`
  - البيوت: `houses=house|home|cottage|cabin|hut|building|villa`
  - الشخصيات: `characters=character|npc|player|human|knight|zombie|enemy|hero`
  - الصخور: `rocks=rock|stone|boulder|cliff|pebble`
- `--exclude lod,collision` removes unwanted variants. `--no-content-match` disables internal-name search. `--substring` = raw substring matching.
- Layout: default `smart` (`<label>/<ext>/file` with `--match`, else `<category>/<ext>/file`); `--layout source` keeps original structure.
- Preview without writing results: `--list-only`.

## Rules
- Never write into or delete the user's input files; the tool already opens them read-only. Never run it with `-o` inside an input folder you care about.
- Matching is name-based; it cannot see what a model looks like. After extraction, say so and list what was matched so the user can check.
- Passworded, multi-part (`.part1.rar`, `.z01`, `.7z.001`) archives are unsupported — report them, don't pretend.
- If you change the tool, run `python -m pytest tests` and report the real result.
