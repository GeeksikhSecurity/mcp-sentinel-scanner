# Not a Prose Contract

This is a plain markdown file that lives in the fixtures directory but has no `.prose.md` extension. The detector must skip it. If the detector emits any finding for this file, the file-extension filter is broken.

```yaml
---
name: looks-like-frontmatter
kind: system
---
```

Even with frontmatter-looking content in a code block, this file is not a Prose contract because its extension is `.md`, not `.prose.md`.

### Requires

- nothing

### Ensures

- nothing

(These section headers exist as a tripwire. A detector that does not filter on the `.prose.md` extension would falsely flag this file.)
