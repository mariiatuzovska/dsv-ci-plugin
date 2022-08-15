# DSV CI plugin

Delinea DevOps Secrets Vault (DSV) CI plugin allows you to access and reference your Secrets data available for use in GitHub Actions or in GitLab Jobs.

## Inputs

| Name           | Description |
| ---------------| ------------|
| `domain`       | Tenant domain name (e.g. example.secretsvaultcloud.com). |
| `clientId`     | Client ID for authentication. |
| `clientSecret` | Client Secret for authentication. |
| `setEnv`       | Set environment variables. |
| `retrieve`     | Data to retrieve from DSV in format `<path> <data key> as <output key>`. |


## GitHub usage

```yaml
steps:
- name: Read secrets from DSV
  id: dsv
  uses: mariiatuzovska/dsv-ci-plugin@v6.0
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

## GitLab usage

```yaml
stages:
  - my_stage

retrieve_secrets:
    image: 
      name: mariiatuzovska/dsv-ci-plugin:v1.0
    stage: my_stage
    # setup input variables
    variables:
        DOMAIN: $DOMAIN
        CLIENT_ID: $CLIENT_ID
        CLIENT_SECRET: $CLIENT_SECRET
        RETRIEVE: |
            $SECRET_PATH $MY_SECRET_KEY_1 AS secretval
            $SECRET_PATH $MY_SECRET_KEY_2 AS mysecret
            $SECRET_PATH $MY_SECRET_KEY_3 AS myval

    # run docker image with input variables
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
    - job: retrieve_secrets
      artifacts: true

```

## Licensing

[MIT License](https://github.com/mariiatuzovska/secret-vault-github-action-plugin/blob/master/LICENSE).
