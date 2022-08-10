# DSV GitHub Action

Delinea DevOps Secrets Vault (DSV) GitHub Action allows you to access and reference your Secrets data available for use in GitHub Actions.

## Usage

```
steps:
- name: Read secrets from DSV
  id: dsv
  uses: mariiatuzovska/secret-vault-github-action-plugin@v0.10.0
  with:
    domain: ${{ secrets.DSV_SERVER }}
    clientId: ${{ secrets.DSV_CLIENT_ID }}
    clientSecret: ${{ secrets.DSV_CLIENT_SECRET }}
    setEnv: true
    retrieve: |
      ${{ secrets.DSV_SECRET_PATH_ONE }} ${{ secrets.DSV_SECRET_KEY_ONE }} AS myVal1
      ${{ secrets.DSV_SECRET_PATH_TWO }} ${{ secrets.DSV_SECRET_KEY_TWO }} AS myVal2

- name: Print secret referencing ID of the step.
  run: echo ${{ steps.dsv.outputs.myVal1 }}

- name: Print secret using environment virable (only available if `setEnv` was set to `true`)
  run: echo ${{ env.myVal2 }}
```

## Licensing

[MIT License](https://github.com/mariiatuzovska/secret-vault-github-action-plugin/blob/master/LICENSE).
