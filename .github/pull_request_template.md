## What does this change?

<!-- A short description. Link related issues with "Fixes #123". -->

## Type

- [ ] Preset
- [ ] Signature (evidence included below)
- [ ] Verdict logic
- [ ] Translation
- [ ] Bug fix
- [ ] Docs
- [ ] Other

## Evidence / testing

<!--
For signatures: the captured response, where and when it was seen.
For verdict changes: the situation that was misdiagnosed and the new test.
-->

## Checklist

- [ ] `go test ./...` passes
- [ ] `go vet ./...` and `gofmt -l .` are clean
- [ ] New messages exist in English and Persian
- [ ] Docs updated (README.md, README.fa.md, docs/) if behaviour changed
- [ ] No telemetry, no new network destinations beyond the documented ones
