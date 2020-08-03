admin
-----

## API

### Create API Keys

#### Request

```js
{
  "create-key": {
    "tenant_id": "<id>",
    "tenant_name": "<name>",
    "application_name": "<name>",
    "created_by": "<name>"
  }
}

```

#### Response

```js
{
  "statusCode: "200",
  "body": {
    "key_id": "<id>",
    "private_key": "<body>"
  }
}
```

```js
{
  "statusCode": "400",
  "body": "tenant_id is required"
}
```

### Delete API Key

#### Request

```js
{
  "delete": {
    "key_id": "<key-id>"
  }
}

```

#### Response

```js
{
  "statusCode": "200",
  "body": "Ok"
}
```
