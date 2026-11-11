# Marketing font

The marketing page uses a Latin Inter variable subset. Its character coverage,
weight range (400–800), and optical-size range (14–32) are preserved. Optional
OpenType stylistic and numeric variants unused by the marketing stylesheet are
omitted; default contextual shaping and kerning remain available.

The complete Inter font and its SIL Open Font License remain in `public/fonts`.
The application pages retain their existing font configuration.

To reproduce the marketing subset with FontTools 4.42.1 and WOFF2 support:

```sh
font_work=$(mktemp -d)
git show 7e4a08cd8c9cac935398bddd1d1a2d4497a5e2ba:public/fonts/InterVariable-latin.woff2 > "$font_work/InterVariable-latin.woff2"
pyftsubset "$font_work/InterVariable-latin.woff2" --unicodes='*' --flavor=woff2 --output-file=public/fonts/InterVariable-latin.woff2
rm "$font_work/InterVariable-latin.woff2"
rmdir "$font_work"
```

Before changing this asset, check the marketing CSS for newly enabled font
features. Preserve character coverage, and compare shaping and visual layout
across the supported weight and optical-size ranges.
