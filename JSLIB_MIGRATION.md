# Migrating from xk6-cognito-srp

This guide replaces the custom [`xk6-cognito-srp`](https://github.com/OS-jyothikaspa/xk6-cognito-srp)
extension with the Cognito client in `k6-jslib-aws`. The JavaScript library
does not require a custom k6 binary.

## Current extension code

Remove the extension import and its `connect()`/`auth()` calls:

```javascript
import cognito from "k6/x/cognito-srp";

const client = cognito.connect(__ENV.AWS_REGION);

export default function () {
  const tokens = client.auth(
    __ENV.COGNITO_USERNAME,
    __ENV.COGNITO_PASSWORD,
    __ENV.COGNITO_USER_POOL_ID,
    __ENV.COGNITO_CLIENT_ID,
    {},
  );

  // tokens.AccessToken, tokens.IdToken, tokens.RefreshToken
}
```

## k6-jslib-aws code

Import the Cognito client and configuration from the version of
`k6-jslib-aws` that includes Cognito support:

```javascript
import {
  AWSConfig,
  CognitoIdentityProviderClient,
} from "https://jslib.k6.io/aws/<version>/cognito.js";

const config = new AWSConfig({
  region: __ENV.AWS_REGION,
  accessKeyId: __ENV.AWS_ACCESS_KEY_ID,
  secretAccessKey: __ENV.AWS_SECRET_ACCESS_KEY,
});

const cognito = new CognitoIdentityProviderClient(config);

export default async function () {
  const tokens = await cognito.authenticateUser(
    __ENV.COGNITO_USERNAME,
    __ENV.COGNITO_PASSWORD,
    __ENV.COGNITO_USER_POOL_ID,
    __ENV.COGNITO_CLIENT_ID,
  );

  // tokens.AccessToken, tokens.IdToken, tokens.RefreshToken
}
```

Replace `<version>` with the released `k6-jslib-aws` version that includes the
Cognito client. Unlike the extension's `auth()` method, `authenticateUser()`
is asynchronous and must be awaited.

## App-client secrets and SMS MFA

Pass an options object as the fifth argument when the Cognito app client has a
secret or the user must answer an SMS MFA challenge:

```javascript
const tokens = await cognito.authenticateUser(
  __ENV.COGNITO_USERNAME,
  __ENV.COGNITO_PASSWORD,
  __ENV.COGNITO_USER_POOL_ID,
  __ENV.COGNITO_CLIENT_ID,
  {
    clientSecret: __ENV.COGNITO_CLIENT_SECRET,
    mfaCode: __ENV.COGNITO_MFA_CODE,
  },
);
```

Omit either property when it does not apply.
