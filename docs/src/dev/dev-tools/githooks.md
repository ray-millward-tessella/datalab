# Git Hooks

## eslint

A git hook has been created to lint all staged files with the `.js` extension on execution
of the `git commit` command and will prevent the commit if the eslint fails. This git hook
is defined in the [Data Lab Web Application](../datalab-app/README.md) `package.json` and
requires a `yarn install` to function. This functionality is provided by the __npm__
packages `lint-staged` and `husky`, and the `.lintstagedrc` configuration file.

To commit without validation via the git hooks using the following command.

```bash
git commit --no-verify
```

To permanently disable the git hook remove the `"precommit": "lint-staged"` line from
scripts in `code/datalab-app/package.json`.