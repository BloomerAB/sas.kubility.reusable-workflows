# [Reusable Workflows](https://docs.github.com/en/actions/learn-github-actions/reusing-workflows)
These are workflows that can be used from other workflows in the same organisation.

Call them like a job:


    <job-name>:
      uses:{owner}/{repo}/{path}/{filename}@{ref}
      with:
        inputs:
          ...
        secrets:
          ...

## Local development
Some useful tools for local development.

### Act
When developing locally you can use [act](https://github.com/nektos/act) to test your workflows. Unfortunately, At the time (2021-11-03) It's not possible to trigger a reusable workflow locally, But you can always test them individually by changing the `workflow_call:` trigger to e.g. `pull_request:` and then run that specific workflow.

### GitHub CLI
Workflows can be triggered by using the [GitHub CLI](https://github.com/cli/cli).

    gh workflow run [<workflow-id> | <workflow-name>] --ref <branch> --repo <organization>/<repository>


Example:

    gh workflow run "Manifest Validation" --ref feature/manifest-validation-workflow --repo BloomerAB/sas.platform.observability-k8s-config