oauth2-jwt
==========

[![Build status](https://badge.buildkite.com/3c3947d186528528143852895378ae1808e68766220f41e17b.svg?branch=master)](https://buildkite.com/formationai/oauth2-jwt)

```
OAuth 2.0 JSON Web Token flow, commonly known as "two-legged OAuth 2.0"
```

See: [https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12)




## Code

`client` - Designed to be used with clients interacting with APIs externally

`integration` - end to end integration test of oauth workflow

`server` - resources for support `authorization-grant` endpoint

`edge` - library for edge services to validate requests

`store` - backing store for long live key storage


### Using OAuth 2.0 to Access Formation APIs

#### Basic Steps

Related [google oauth 2.0 flow](https://developers.google.com/identity/protocols/oauth2#basicsteps)

1. Obtain OAuth 2.0 Credentials from the console

2. Obtain an access token from the Formation Authorization Server.

3. Send the access token to an API.

4. Refresh the access token, if necessary.


#### Detailed Steps

##### 1. Obtain OAuth 2.0 Credentials from the console

`see UI documentation`

##### 2. Obtain an access token from the Formation Authorization Server.

```
Preparing to make an authorized API call
```

Related [google documentation](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)

1. Obtain the client ID and private key from the console

2. Create a JSON Web Token which includes a header, a claim set, and a signature.

3. Request an access token from the Formation OAuth 2.0 Authorization Server.

4. Handle the JSON response that the Authorization Server returns.

![flow](https://developers.google.com/accounts/images/serviceaccount.png)


##### 3. Send the access token to an API.

```
Calling APIs
```

Related [google documentation](https://developers.google.com/identity/protocols/oauth2/service-account#callinganapi)

Include the access token in a request to the API by including an `Authorization` HTTP header `Bearer` value.

`curl` example

```shell
curl -H "Authorization: Bearer access_token" $ENDPOINT
```


##### 4. Refresh the access token, if necessary.

Access tokens issued by the Formation OAuth 2.0 Authorization Server
after the duration provided by the expires_in value. When an access
token expires, then the application should generate another JWT, sign
it, and request another access token.


### Standards

Will be implemented with ietf standards.

  - OAuth2 2.0 Protocol - [rfc6749](https://tools.ietf.org/html/rfc6749)

  - Granting short lived bearer tokens (AuthZ scoping) - [rfc7523#section-2.1](https://tools.ietf.org/html/rfc7523#section-2.1)

  - JWT format and signature - [rfc7519](https://tools.ietf.org/html/rfc7519)

  - Claims defined by OAuth2 JWT Profile - [rfc7523](https://tools.ietf.org/html/rfc7523)

  - Server validation of signed request - [rfc7523#section-3](https://tools.ietf.org/html/rfc7523#section-3)

Follows the OAuth2 2.0 flow.

  - https://developers.google.com/identity/protocols/oauth2#serviceaccount

  - https://developers.google.com/identity/protocols/oauth2/service-account#httprest



## Setup environment

```
go run ./util server-bootstrap
```

Store in secrets manager: `<env>/private-key`

Store public key for edge services

```
echo '<public-key>' | base64 -w 0
```
