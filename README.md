# DSV CI plugin

[Delinea DevOps Secrets Vault (DSV)](https://delinea.com/products/devops-secrets-management-vault)
CI plugin allows you to access and reference your Secrets data available for use in GitHub Actions
or in GitLab Jobs.

- [Inputs](#inputs)
- [Prerequisites](#prerequisites)
- [GitHub usage example](#github-usage-example)
- [GitLab usage example](#gitlab-usage-example)
- [Licensing](#licensing)

## Inputs

| Name           | Description |
| ---------------| ------------|
| `domain`       | Tenant domain name (e.g. example.secretsvaultcloud.com). |
| `clientId`     | Client ID for authentication. |
| `clientSecret` | Client Secret for authentication. |
| `setEnv`       | Set environment variables. Applicable only for GitHub Actions. |
| `retrieve`     | Data to retrieve from DSV in format `<path> <data key> as <output key>`. |

## Prerequisites

This plugin uses authentication based on Client Credentials, i.e. via Client ID and Client Secret.

You can generate Client Credentials using a command-line interface (CLI) tool. Latest version of
the CLI tool can be found here: https://dsv.secretsvaultcloud.com/downloads. Quick start with
the CLI: https://docs.delinea.com/dsv/current/quickstart.

To create a role run:

```
$ dsv role create --name <role name>
```

To generate a pair of Client ID and Client Secret run:

```
$ dsv client create --role <role name>
```

Use returned values of Client ID and Client Secret to configure this plugin. After this you can
create secrets for the pipeline and configure access to those secrets.

Example of configuration:

```
# Create a role named "ci-reader":
$ dsv role create --name ci-reader

# Generate client credentials for the role:
$ dsv client create --role ci-reader

# Create a secret:
$ dsv secret create \
  --path 'ci-secrets:secret1' \
  --data '{"password":"foo","token":"bar"}'

# Create a policy to allow role "ci-reader" to read secrets under "ci-secrets":
$ dsv policy create \
  --path 'secrets:ci-secrets' \
  --actions 'read' \
  --effect 'allow' \
  --subjects 'roles:ci-reader'
```


## GitHub usage example

```yaml
steps:
- name: Read secrets from DSV
  id: dsv
  uses: mariiatuzovska/dsv-ci-plugin@v6.2
  with:
    domain: ${{ secrets.DSV_SERVER }}
    clientId: ${{ secrets.DSV_CLIENT_ID }}
    clientSecret: ${{ secrets.DSV_CLIENT_SECRET }}
    setEnv: true
    retrieve: |
      ${{ secrets.DSV_SECRET_PATH_ONE }} ${{ secrets.DSV_SECRET_KEY_ONE }} AS myVal1
      ${{ secrets.DSV_SECRET_PATH_TWO }} ${{ secrets.DSV_SECRET_KEY_TWO }} AS MYVAL2

- name: Print secret referencing ID of the step.
  run: echo ${{ steps.dsv.outputs.myVal1 }}

- name: Print secret using environment virable (only available if `setEnv` was set to `true`)
  run: echo ${{ env.MYVAL2 }}
```

## GitLab usage example

```yaml
stages:
  - my_stage

dsv_secrets:
    image: 
      name: mariiatuzovska/dsv-ci-plugin:v1.2
    stage: my_stage
    variables:
        DOMAIN: $DOMAIN
        CLIENT_ID: $CLIENT_ID
        CLIENT_SECRET: $CLIENT_SECRET
        RETRIEVE: |
            $SECRET_PATH $MY_SECRET_KEY_1 AS secretval
            $SECRET_PATH $MY_SECRET_KEY_2 AS mysecret
            $SECRET_PATH $MY_SECRET_KEY_3 AS myval
    script:
        - ""
    artifacts:
        reports:
          dotenv: $CI_JOB_NAME

test:
    stage: my_stage
    script:
      - echo "test"
      - echo $SECRETVAL
      - echo $MYSECRET
      - echo $MYVAL
    needs:
    - job: dsv_secrets
      artifacts: true

```

## Licensing

[MIT License](https://github.com/mariiatuzovska/secret-vault-github-action-plugin/blob/master/LICENSE).
