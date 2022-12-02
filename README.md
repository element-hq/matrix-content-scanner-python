# Matrix Content Scanner

A web service for scanning media hosted on a Matrix media repository.

## Installation

This project requires libolm development headers, as well as libmagic to be installed on
the system. On Debian/Ubuntu:

```commandline
sudo apt install libolm-dev libmagic1
```

Then, preferably in a virtual environment, install the Matrix Content Scanner:

```commandline
pip install matrix-content-scanner
```

## Usage

Copy and edit the [sample configuration file](https://github.com/matrix-org/matrix-content-scanner-python/blob/main/config.sample.yaml).
Each key is documented in this file.

Then run the content scanner (from within your virtual environment if one was created):

```commandline
python -m matrix_content_scanner.mcs -c CONFIG_FILE
```

Where `CONFIG_FILE` is the path to your configuration file.

## Docker

This project provides a Docker image to run it, published as
`vectorim/matrix-content-scanner`.

To use it, copy the [sample configuration file](/config.sample.yaml) into a dedicated
directory, edit it accordingly with your requirements, and then mount this directory as
`/data` in the image. Do not forget to also publish the port that the content scanner's
Web server is configured to listen on.

For example, assuming the port for the Web server is `8080`:

```shell
docker run -p 8080:8080 -v /path/to/your/config/directory:/data vectorim/matrix-content-scanner
```

## API

See [the API documentation](/docs/api.md) for information about how clients are expected
to interact with the Matrix Content Scanner.

## Migrating from the [legacy Matrix Content Scanner](https://github.com/matrix-org/matrix-content-scanner)

Because it uses the same APIs and Olm pickle format as the legacy Matrix Content Scanner,
this project can be used as a drop-in replacement. The only change (apart from the
deployment instructions) is the configuration format:

* the `server` section is renamed `web`
* `scan.tempDirectory` is renamed `scan.temp_directory`
* `scan.baseUrl` is renamed `download.base_homeserver_url` (and becomes optional)
* `scan.doNotCacheExitCodes` is renamed `result_cache.exit_codes_to_ignore`
* `scan.directDownload` is removed. Direct download always happens when `download.base_homeserver_url`
  is absent from the configuration file, and setting a value for it will always cause files to be
  downloaded from the server configured.
* `proxy` is renamed `download.proxy`
* `middleware.encryptedBody.pickleKey` is renamed `crypto.pickle_key`
* `middleware.encryptedBody.picklePath` is renamed `crypto.pickle_path`
* `acceptedMimeType` is renamed `scan.allowed_mimetypes`
* `requestHeader` is renamed `download.additional_headers` and turned into a dictionary.

Note that the format of the cryptographic pickle file and key are compatible between
this project and the legacy Matrix Content Scanner. If no file exist at that path one will
be created automatically.

## Development

In a virtual environment with pip ≥ 21.1, run
```shell
pip install -e .[dev]
```

To run the unit tests, you can either use:
```shell
tox -e py
```
or
```shell
trial tests
```

To run the linters and `mypy` type checker, use `./scripts-dev/lint.sh`.


## Releasing

The exact steps for releasing will vary; but this is an approach taken by the
Synapse developers (assuming a Unix-like shell):

 1. Set a shell variable to the version you are releasing (this just makes
    subsequent steps easier):
    ```shell
    version=X.Y.Z
    ```

 2. Update `setup.cfg` so that the `version` is correct.

 3. Stage the changed files and commit.
    ```shell
    git add -u
    git commit -m v$version -n
    ```

 4. Push your changes.
    ```shell
    git push
    ```

 5. When ready, create a signed tag for the release:
    ```shell
    git tag -s v$version
    ```
    Base the tag message on the changelog.

 6. Push the tag.
    ```shell
    git push origin tag v$version
    ```

 7. Create a *release*, based on the tag you just pushed, on GitHub or GitLab.

 8. Create a source distribution and upload it to PyPI:
    ```shell
    python -m build
    twine upload dist/matrix_content_scanner-$version*
    ```
