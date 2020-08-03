store
-----


### Tables

#### `state`

- `identity-id` counter

#### `applications`

Pkey:
  - `tenant-id`#`application-name`

Attributes:
  - `application-id`

#### `keys`

Pkey:
  - `keyid`

Attributes:
  - `public-key`
  - `identity-id`
  - `tenant-id`

### Flow

#### Create Key

  1) Get `application-id` from `applications`

  2) if missing: upsert `identity-id` counter in `state` and create item in `applications`

  3) Create item in `keys`
