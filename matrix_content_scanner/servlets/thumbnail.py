#  Copyright 2022 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from typing import TYPE_CHECKING, Dict, List, Tuple, Union

from twisted.web.http import Request

from matrix_content_scanner import logutils
from matrix_content_scanner.servlets import BytesResource
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class ThumbnailServlet(BytesResource):
    """Handles GET requests to .../thumbnail/serverName/mediaId"""

    isLeaf = True

    def __init__(self, content_scanner: "MatrixContentScanner"):
        super().__init__()
        self._scanner = content_scanner.scanner

    async def on_GET(self, request: Request) -> Tuple[int, Union[bytes, JsonDict]]:
        # mypy doesn't recognise request.postpath but it does exist and is documented.
        media_path_bytes: bytes = b"/".join(request.postpath)  # type: ignore[attr-defined]
        media_path = media_path_bytes.decode("ascii")
        logutils.set_media_path_in_context(media_path)

        # request.args stores all keys and values as bytes. However, we want them to be
        # string going forward, so we convert them now.
        thumbnail_params: Dict[str, List[str]] = {}
        for key, values in request.args.items():
            str_values: List[str] = []
            for value in values:
                str_values.append(value.decode("utf-8"))
            thumbnail_params[key.decode("utf-8")] = str_values

        media = await self._scanner.scan_file(
            media_path=media_path,
            thumbnail_params=thumbnail_params,
        )
        request.responseHeaders = media.response_headers
        return 200, media.content
