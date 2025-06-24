# Matrix Content Scanner API

This document describes the custom API implemented by the Matrix Content Scanner.

## Error codes

An error is returned as JSON responses to the request that caused it, in the following format:

| Parameter | Type | Description                                            |
|-----------|------|--------------------------------------------------------|
| `reason`  | str  | The machine-readable code for the error.               |
| `info`    | str  | Additional human-readable information about the error. |

Example:

```json
{
    "info": "***VIRUS DETECTED***",
    "reason": "MCS_MEDIA_NOT_CLEAN"
}
```

The error codes used by the Matrix Content Scanner are described below, alongside the HTTP
status code of the response for each scenario:

| Status Code | Reason                        | Description                                                                                                                                                                       |
|-------------|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 400         | `MCS_MALFORMED_JSON`          | The request body contains malformed JSON.                                                                                                                                         |
| 400         | `MCS_MEDIA_FAILED_TO_DECRYPT` | The server failed to decrypt the encrypted media downloaded from the media repo.                                                                                                  |
| 401         | `M_MISSING_TOKEN`             | The request is missing a required access token for authentication.                                                                                                                |
| 401         | `M_UNKNOWN_TOKEN`             | The access token provided for authentication is not valid.                                                                                                                        |
| 404         | `M_NOT_FOUND`                 | The `Authorization` header was missing when requesting authenticated media.                                                                                                       |
| 404         | `M_NOT_FOUND`                 | No route could be found at the given path.                                                                                                                                        |
| 404         | `M_NOT_FOUND`                 | The requested media was not present in the media repo.                                                                                                                            |
| 403         | `MCS_MEDIA_NOT_CLEAN`         | The server scanned the downloaded media but the antivirus script returned a non-zero exit code.                                                                                   |
| 403         | `MCS_MIME_TYPE_FORBIDDEN`     | The Mime type is not in the allowed list of Mime types.                                                                                                                           |
| 403         | `MCS_BAD_DECRYPTION`          | The provided `encrypted_body` could not be decrypted, or the encrypted file could not be decrypted. The client should request the public key of the server and then retry (once). |
| 500         | `M_UNKNOWN`                   | The server experienced an unexpected error.                                                                                                                                       |
| 502         | `MCS_MEDIA_REQUEST_FAILED`    | The server failed to request media from the media repo.                                                                                                                           |


## Routes


### `GET /_matrix/media_proxy/unstable/download/{serverName}/{mediaId}`

Downloads the media at `mxc://{serverName}/{mediaId}` and scans it. If the scan is
successful, the media is sent in the response (identical to the
`GET /_matrix/media/v3/download/...` route in the Matrix specification). If the scan is
unsuccessful, an error is sent with the reason `MCS_MEDIA_NOT_CLEAN`.


### `GET /_matrix/media_proxy/unstable/thumbnail/{serverName}/{mediaId}`

Takes the query parameters described [in the Matrix specification](https://spec.matrix.org/latest/client-server-api/#get_matrixmediav3thumbnailservernamemediaid).

Downloads a thumbnail of the media at `mxc://{serverName}/{mediaId}` and scans it. If the
scan is successful, the media is sent in the response (identical to the
`GET /_matrix/media/v3/thumbnail/...` route in the Matrix specification). If the scan is
unsuccessful, an error is sent with the reason `MCS_MEDIA_NOT_CLEAN`.


### `GET /_matrix/media_proxy/unstable/scan/{serverName}/{mediaId}`

Downloads the media at `mxc://{serverName}/{mediaId}`, scans it and
responds with the result of the scan.

Response format:

| Parameter | Type | Description                                                        |
|-----------|------|--------------------------------------------------------------------|
| `clean`   | bool | The scan's result: `true` if the file is clean, `false` otherwise. |
| `info`    | str  | Human-readable information about the result.                       |

Example:

```json
{
    "clean": false,
    "info": "***VIRUS DETECTED***"
}
```


### `POST /_matrix/media_proxy/unstable/download_encrypted`

Downloads a specified encrypted file, decrypts it and then behaves identically to the
`GET /_matrix/media_proxy/unstable/download/{serverName}/{mediaId}` route.

Request body:

| Parameter        | Type          | Description                                                                                                                                                                                                                                                                                |
|------------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `encrypted_body` | EncryptedBody | An Olm-encrypted version of the request body. See [this section](#encrypted-post-body) for more information.                                                                                                                                                                               |
| `file`           | EncryptedFile | The metadata (download MXC URL and decryption key) of an encrypted file. Follows the format of the `EncryptedFile` structure from the [Matrix specification](https://spec.matrix.org/v1.2/client-server-api/#extensions-to-mroommessage-msgtypes). Ignored if `encrypted_body` is present. |

Example:

```json
{
    "file": {
        "v": "v2",
        "key": {
            "alg": "A256CTR",
            "ext": true,
            "k": "qcHVMSgYg-71CauWBezXI5qkaRb0LuIy-Wx5kIaHMIA",
            "key_ops": [
                "encrypt",
                "decrypt"
            ],
            "kty": "oct"
        },
        "iv": "X85+XgHN+HEAAAAAAAAAAA",
        "hashes": {
            "sha256": "5qG4fFnbbVdlAB1Q72JDKwCagV6Dbkx9uds4rSak37c"
        },
        "url": "mxc://matrix.org/oSTbuSlyZKXvgtbtUsPxRbto"
    }
}
```


### `POST /_matrix/media_proxy/unstable/scan_encrypted`

Downloads a specified encrypted file, decrypts it and then behaves identically to the
`GET /_matrix/media_proxy/unstable/scan/{serverName}/{mediaId}` route.

The request body for this route is the same as for
`POST /_matrix/media_proxy/unstable/download_encrypted`.


### `GET /_matrix/media_proxy/unstable/public_key`

Responds with a base64 representation of the public key to use to generate the
`encrypted_body` parameter of POST requests. See [this section](#encrypted-post-body) for
more information.

Response format:

| Parameter    | Type | Description                                |
|:-------------|------|--------------------------------------------|
| `public_key` | str  | A base64 representation of the public key. |

Example:

```json
{
    "public_key": "GdwYYj5Ey9O96FMi4DjIhPhY604RuZg2Om98Kqh+3GE"
}
```


## Encrypted POST body

When processing encrypted attachments, there are two ways to communicate the metadata
(i.e. URL and decryption key for the file) to the Matrix Content Scanner.

The first one is by sending it in the request body as shown above. However, this might not
provide enough security depending on the infrastructure the Matrix Content Scanner is
deployed in. For example if translation from HTTPS to HTTP is done on a separate machine
than the one hosting the Matrix Content Scanner, it might be a concern that other pieces
of the infrastructure might be able to intercept this traffic and decrypt the attachment.

The second way of communicating encrypted file metadata is to first encrypt it using
vodozemac's [`PkEncryption`](https://github.com/matrix-org/vodozemac/blob/main/src/pk_encryption.rs#L287)
class. This is done using the public key retrieved from
`GET /_matrix/media_proxy/unstable/public_key` and sending the resulting encrypted message
in an `encrypted_body` parameter of the request's body. This parameter follows this format:

| Parameter    | Type | Description            |
|--------------|------|------------------------|
| `ciphertext` | str  | The encrypted content. |
| `mac`        | str  | The MAC.               |
| `ephemeral`  | str  | The ephemeral key.     |

Example (generated using the body and public key from the previous examples):

```json
{
    "encrypted_body": {
        "ciphertext": "tED6iNpKcZti+HMZ6t1M+ZlE27IbvF9nojz59dg3jtJHv/9wtH6KiYyaZsVvCNzuwWCjdcxA4PMevZuWnVIEWHArCKdcFJeAvzxzlVtFvlgM5PIiTNtkh8sXIaC7RP5+3s0/aQs9PhuhlJ5nGlS86BZJ56dDwQWS5DO/WPqsTko9lz6//XtZ8ko417vybz81NTNpoADRc8XRntsI1+rmdKkXJtuXTA3d46CCAhLvoJLZlk7xb7IGHADk3eYQ9WTaKQ76/PW1dDo5xQGyXOr+lJByisjkoz4C8i4wRYXnks+d3q6kIndGZgO8s/H7/kfYC052IAlAk3LmYavXaNwXJtnWUCCakTHME154yup8DtmsyuZkC3p3KhSsKAeoxmYvsSf0+p0MinOWB4BgeWwaBaKDKTHbaUKwQzdbZrBXKP+QBdmM9PUrmsTPR2RmWRsPCC3dcmz4rakCZB/Xvwg++xDzpxi3+iJxJ011g1Dfp4sd44U6LJDVZafIoPu7esChYD4o+x4tP4airHueLGpP0rQxPuDZRvklwCRZ5xtzr47fINel2IGrTQEPyNES+lASGr2xeWwBJXBe47OkM0rXZn1HVM6iK3g3HfUT6pFhdI/52ztUf+gOhOhRvTpP079Je9INLApXSu793EQGJpH+ms3ymJ3mfBhEYVVnj8zbczo",
        "mac": "nipjbUCnIEw",
        "ephemeral": "fk2xOTmttnFDTAORxVQTtIlbsu7O01Oe52+umaOjIiE"
    }
}
```

## Authenticated Media

When accessing media from a Synapse homeserver with authenticated media enabled, an
`Authorization` HTTP header must be passed along with any request to the Matrix Content Scanner.
If the `Authorization` header is not present, the content scanner assumes the request is not an
authenticated media request and will use the old Matrix endpoints.

This header follows the `Authentication Bearer scheme` as [outlined in the Matrix specification](https://spec.matrix.org/v1.12/client-server-api/#using-access-tokens).
The `access_token` must be the Matrix access token of the client's user.
The `Authorization` header method must be used, sending the access token as a query string
parameter is not supported.

Example authorization header:

```
Authorization: Bearer <access_token>
```
