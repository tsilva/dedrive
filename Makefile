release-%:
	hatch version $*
	git add dedrive/__init__.py
	git commit -m "chore: release $$(hatch version)"
	git push
