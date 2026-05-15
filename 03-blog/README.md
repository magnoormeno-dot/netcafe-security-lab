# CafeSec Lab Research Notes

This directory contains the Jekyll blog for CafeSec Lab.

The blog is written in English and focuses on defensive research for internet cafes, gaming venues, esports hotels, and managed shared-PC environments.

## Local Preview

```bash
bundle install
bundle exec jekyll serve
```

The `_config.yml` enables future posts because the project charter includes one planned article dated after the current creation date.

## GitHub Pages Deployment

The repository publishes this directory through `.github/workflows/pages.yml`.
The production URL is configured as:

```text
https://magnoormeno-dot.github.io/netcafe-security-lab/
```

Use `workflow_dispatch` for a manual rebuild after changing Pages settings, or push changes under `03-blog/` to trigger deployment automatically.
