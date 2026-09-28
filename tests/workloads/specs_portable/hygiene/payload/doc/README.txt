This file is OUTSIDE the source directory, so an install that promotes the
payload minus its sourceDir carries it. It is here to be the control for the
build-only files in src/: without something that MUST be installed, a check
that nothing was installed would pass trivially.
