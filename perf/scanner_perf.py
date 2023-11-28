#! /usr/bin/env python

"""
This script is a rudimentary end-to-end test of the content scanner. It starts the
content scanner as a subprocess, using the hard-coded config.yaml. The scanner is
configured with matrix.org as its upstream homserver, and to use a dummy scanning script
which just calls `sleep 1`.

Next, we concurrently request Matrix Avatar URLs taken from the public
#synapse-dev:matrix.org room. (The URLs are hard-coded in this file. It's ugly, but good
enough for now.)

We wait for the content scanner to finish responding to reach response, reading the
response bodies from the scanner. We print how long (wall clock) it took to do so,
and close the content scanner subprocess.
"""

import asyncio
import collections
import os.path
import subprocess
import sys
import time
import timeit
import traceback

import aiohttp

timer = timeit.default_timer

AVATAR_URLS_TAKEN_FROM_SYNAPSE_DEV = [
    "http://127.0.0.1:8080/ipfs/QmfS3zCyhM4KgvYWH1HrD1Rnumns7fyTzcSHjk5fsWe5ZH?filename=IMG_20230222_191003_e_1677506180005.jpg",
    "mxc://1312.media/SQdCZTnJfLkBAxgQMPkVgsPY",
    "mxc://abolivier.bzh/zPatuAFfwaXVxsJudPWkFcWF",
    "mxc://aguiarvieira.pt/74665ee95b29e2a217b88911cfc664a1ccbb7e141703097801866477568",
    "mxc://amorgan.xyz/JHlaCvKzIPrlcnYWTFoOqsmH",
    "mxc://asra.gr/4f06832b1418d4c5ba91cae68135592754841080",
    "mxc://automattic.com/cf00594221369ad4498eb3b73032969c7be0fa3b",
    "mxc://b3.hk/kKAHEhEOFMyXHQCcSFuQOQza",
    "mxc://beeper.com/18850ea089e0ecc16d7db55527925b43ad63295c",
    "mxc://beeper.com/c2ef30e46e6f99cd913f2b632573033c60a74524",
    "mxc://bolha.chat/BevcFWoBVCMGMGqYQNhVddfu",
    "mxc://bolha.chat/ClRsLphUvHmWHWOFjKLwiknN",
    "mxc://bonifacelabs.ca/WjbmLXYLDRPxUzorCdExENVZ",
    "mxc://bramen.com.co/oTFgSIkJdDTBIcuvtWTukatz",
    "mxc://brodi.me/PPjyGXrcCqcwRrKpYoIgLvgw",
    "mxc://cadair.com/LdiPRXiYOVpdWvURyocZmvUo",
    "mxc://chat.decatrion.com/MXOQjcRSnVSqOALFTDlgIKnq",
    "mxc://chat.interru.io/UJdEhRreNufARVwpCAGWnHTx",
    "mxc://chat.mistli.net/MIlfZzUpEUelhCLXVFPMacZO",
    "mxc://chat.pyro.monster/bgZxviIdWbBYWInhwZozaryA",
    "mxc://chat.upi.li/rYupYBDqEXxkiQGEhPOiNUGs",
    "mxc://cody.to/hXfwsZbCLswNYgvRDqIQZOnS",
    "mxc://connecteu.rs/8c81538fc306d556bbbce15230b12c68ee7395f8",
    "mxc://cyberia.club/ObtWErjecvRjoCxbEWzHSiXM",
    "mxc://element.io/050bd1fa6777a004eb8ffd6c31028998331a91aa",
    "mxc://element.io/0750b4015ab58d23d704d3a828a1173a175cf95f",
    "mxc://element.io/1fec45ef987253db2728112927562567f8dd9d5e",
    "mxc://element.io/42eff27432ec038e933337dabcdfe3d230b3c68d",
    "mxc://element.io/47465a9ec77dd489e49b6748bc53c4f0122f06d7",
    "mxc://element.io/6130836e26b462a6fe63d4e080dd9d2037490f2b",
    "mxc://element.io/658198ce7f58872cc8fb68862f1eabdc5d847fbc",
    "mxc://element.io/a3f0d8b0868a7bf4e7449141167747a4699109ff",
    "mxc://element.io/bd48d4466c7e21b2ce00836631c06360206c29a0",
    "mxc://element.io/f03df00167d5f7ad5b5eac5375f32146cc2c3f51",
    "mxc://envs.net/89be88bd94378aef18b7f01e6a14d2228cfbb9fa",
    "mxc://envs.net/de405527b5c8dca188d6d8c7f3731e861a9b17ec",
    "mxc://ergaster.org/nmVViTqFqKGGxSHHcwevqnig",
    "mxc://ether.ai/JKGvwPJrfnWiWEIeVGLtJaSl",
    "mxc://fabcity.hamburg/QdttdrpZgTNKcJJWauixXEvQ",
    "mxc://fachschaften.org/c8faf7765794be1b24b3117925ac2464a204fc961726279478688088064",
    "mxc://gatto.club/qEJyuPBKpZITccTfIriEebdK",
    "mxc://gruenhage.xyz/3ecdecdab75225c0a14c7c804061d86962ee1550",
    "mxc://hackerlab.in/vjENMlrncPUGDmbyMZhWJzkG",
    "mxc://hackliberty.org/LeTsthiOdqoNnjOjqWjxWMAI",
    "mxc://half-shot.uk/81696e31e533651fb9e44ce351b4201151042acd",
    "mxc://jacksonchen666.com/pQoQssnTIGKOYHpcWUmYpdsQ",
    "mxc://jameskitt616.one/pBZDFcMKCjVjkrTMgMykKpTi",
    "mxc://jboi.nl/dvVWQixQMJyIQoaLFqFTTpsE",
    "mxc://jki.re/NBtxUkzjXpmdsGychrevxsaB",
    "mxc://lant.uk/MVZeSTcVlpNiDToBuKgyQfIK",
    "mxc://librepush.net/WbEnGmxZGKJyHqbojduVeatQ",
    "mxc://littlevortex.net/jSNRNEyKLRnzYEpsODAUznIZ",
    "mxc://luebke.io/imaijIHMncPjQqYRLtByZRzX",
    "mxc://matrix.0x45.moe/PwcDRntlwelLMuofemYarmqx",
    "mxc://matrix.atommac.com/cAycTPLQEkgtZSlZlRlZXoTx",
    "mxc://matrix.clandestine.network/JpKsGDMkNnSkfQqUdFuoBkFy",
    "mxc://matrix.eclabs.de/KyXZzZTeJyhQDBkqGBcKWyBp",
    "mxc://matrix.f5.htw-berlin.de/LosKszHTJgwslbvrTvNWanwE",
    "mxc://matrix.kevwe.se/PXHQcmOahOjAJoTouFBmevfj",
    "mxc://matrix.m0dex.eu/c2qHa8jqd86MdKplo1VQamYOhkMxkGEl",
    "mxc://matrix.org/AokEDpMKDROUmGwuoErhRIxv",
    "mxc://matrix.org/BORiLtSOEUnZiwCcaJftvxxm",
    "mxc://matrix.org/BugjUgdADNUndQASgkYDHogL",
    "mxc://matrix.org/CLtgiPGknzEpKDiyOrUedmEc",
    "mxc://matrix.org/DIGiJjzKkVsWwpppAcrGRwzB",
    "mxc://matrix.org/DrLDzhkVYvGjfCiUBLkrYLhs",
    "mxc://matrix.org/EbNOzLZJdNszNDDfDrPFvTTx",
    "mxc://matrix.org/FEzUmMhxMsqtfXKyYQFDROgO",
    "mxc://matrix.org/FVaBPAAuzqpBstuOfxDhDuiw",
    "mxc://matrix.org/FwXVuHOTPCJOZwjuunyMoDvw",
    "mxc://matrix.org/GBWoKBFhozIJcuuXzgAmESMh",
    "mxc://matrix.org/GadiqrOaESCBOpqEspzaFHZZ",
    "mxc://matrix.org/GbfNYPPXYfpYDGCPnxEOZACq",
    "mxc://matrix.org/HcOKfHoyUseJyNvJCZbySygK",
    "mxc://matrix.org/HjVgrKzDUXKrzYMDvtglFdvy",
    "mxc://matrix.org/IssHdyiXMcSnRCxCzqoaocGL",
    "mxc://matrix.org/JEPcTsDZpImzoyVdKHfeiUlK",
    "mxc://matrix.org/JQXLHcWNbcbQBMEWebxQPiPT",
    "mxc://matrix.org/JUFinhjLVhQhAmzsSpSaPFiT",
    "mxc://matrix.org/JUssqTzHorMXUbeaulQUNjTm",
    "mxc://matrix.org/KfkLMomWWjVZMbgVCKisfFPy",
    "mxc://matrix.org/LWCDUbJGEqfXWbuACLYPzpMM",
    "mxc://matrix.org/LfpqILSYnaIQDnCqGgrryaVA",
    "mxc://matrix.org/LlsgPelTpiYvvEgjbqKzefbr",
    "mxc://matrix.org/MKYSaqghosWAaMkfOTGqAXWu",
    "mxc://matrix.org/MSSWISKFrXqYAWwVZpgQzKNc",
    "mxc://matrix.org/MhFPyrortOJyjvIArZYRJNpd",
    "mxc://matrix.org/MohmbgPyrsnuKIYJivBLhnaJ",
    "mxc://matrix.org/MygYRbllJEcOXaGOySOEYMJc",
    "mxc://matrix.org/NZGChxcCXbBvgkCNZTLXlpux",
    "mxc://matrix.org/OVXDqAESXvavwJINbuwBeIHy",
    "mxc://matrix.org/PQWXmVjsGPqEgItiYEISwDzI",
    "mxc://matrix.org/QqFWSwNSKvlljlNZKBGrqCKR",
    "mxc://matrix.org/QsaeAloXAKVPsiczXtIBJzrZ",
    "mxc://matrix.org/RMMTwRenYWLPdRwIHlwuGCLG",
    "mxc://matrix.org/RnAJViaJiNHcGtTZgbRWXqlB",
    "mxc://matrix.org/SUpOMAcbPcYBaUnDikHYJOjh",
    "mxc://matrix.org/TGopDZiMVyhwhQBuEbUeFOKt",
    "mxc://matrix.org/TLEyVAuatPchpWniJrgmjUcU",
    "mxc://matrix.org/TlumUuzCcCGHSUMXNJmAFLML",
    "mxc://matrix.org/TpxNfvaFAAoZWdhwoYBHQezB",
    "mxc://matrix.org/VpjGllthGpjTPkvbJgOdyxkF",
    "mxc://matrix.org/WWvqnsZlhzWvPylUjdfhmrOV",
    "mxc://matrix.org/XBkKJIaWeXdfoYwMZsQWKjzj",
    "mxc://matrix.org/XmiRUvkkKjmTseRYrmBlvGNw",
    "mxc://matrix.org/XnDebYmBmnBBNeyBiUKltVlh",
    "mxc://matrix.org/XxylKIkLFThmHZjBMvCmipRT",
    "mxc://matrix.org/YtCeQeNxqnKsLvIcnwKIMlkV",
    "mxc://matrix.org/ZJIdWuBIRhObjOHVnoWfBUkq",
    "mxc://matrix.org/ZafPzsxMJtLaSaJXloBEKiws",
    "mxc://matrix.org/bCawIGTEGxaXxDIxIqteAhVU",
    "mxc://matrix.org/bDayqThxTIcGNcskzIADknRv",
    "mxc://matrix.org/bEVwopEQDMNjfzbiPKYgZXWU",
    "mxc://matrix.org/bHNoSLOERjdQrUodZUIFYAQl",
    "mxc://matrix.org/bSYOldVxWNFeulNUshiOSvlM",
    "mxc://matrix.org/bcBGBuKkVBITyyfjLHLVrPKj",
    "mxc://matrix.org/bipAEyCRqzXokNjHcDwbWXkO#auto",
    "mxc://matrix.org/cKhTXJzIZZjHfNRbNJHjxSxw",
    "mxc://matrix.org/cZEhMcslgpUJdTNMIuQSEukn",
    "mxc://matrix.org/djdngehyFuFlApXWpYotALoK",
    "mxc://matrix.org/eeSkBZDfQavoKeXjWhUGOCrI",
    "mxc://matrix.org/fJYvrULeLqUSuOFFhvAuPbVB",
    "mxc://matrix.org/gJNPpakWLvKGUYteErJnbqRw",
    "mxc://matrix.org/iNUefSlAXjkdNzXyVaYjiiTK",
    "mxc://matrix.org/jRqrnjimPBqTSSdJlOupMqSx",
    "mxc://matrix.org/jVqDFNtFnwfXedjMKZLgtnsY",
    "mxc://matrix.org/kOewGAJWihuVeafiSwgLeiJa",
    "mxc://matrix.org/lyWZOWsBRhCcxKRgVUbDdtux",
    "mxc://matrix.org/mhuskbkCQPvAXCCoZMMcUltg",
    "mxc://matrix.org/nKpRPUortweIAocZOKakSmle",
    "mxc://matrix.org/nwWAiyZHhWuATgUqhXSUgyOq",
    "mxc://matrix.org/oUxxDyzQOHdVDMxgwFzyCWEe",
    "mxc://matrix.org/oqUhSAlhShWRUoOypviZYzCl",
    "mxc://matrix.org/owHbMxnvtZQhORPMIjEMhHJC",
    "mxc://matrix.org/paFLquBfsoSUMExpgOePaYGn",
    "mxc://matrix.org/pcyhRmMTlUPZNUWLBrrBYOUF",
    "mxc://matrix.org/qCJQIqJLUntAlQjvjVqqkISE",
    "mxc://matrix.org/qyoRKkkSwwqoaseeRDCWGmgL",
    "mxc://matrix.org/rAtNyCxKhZKYjIpCMTMVIyZb",
    "mxc://matrix.org/stXVscjfSSwEGcpNUOaTOmuw",
    "mxc://matrix.org/tmemWZxwaiSRLneppvjscbSv",
    "mxc://matrix.org/uFsobEhOojpEXTORyXJznvMf",
    "mxc://matrix.org/wEydarIdYNQoHHnOpfYGQAkZ",
    "mxc://matrix.org/xppypIFIDuFCqmdJHGjTuRsk",
    "mxc://matrix.org/yAEcXFYGUHsLALuVuHtqgsPk",
    "mxc://matrix.org/yCdHqfZAMYzGsSeCYODLGNJQ",
    "mxc://matrix.org/zRHixRxWSlriuAyCEqxKcsUN",
    "mxc://matrix.tarina.org/yQAGQhgyZtbJDzoCxcUoNlte",
    "mxc://maunium.net/jdlSfvudiMSmcRrleeiYjjFO",
    "mxc://mccarty.io/uCPFlUrLVWMrjuZVDnlIzIoI",
    "mxc://medienhaus.dev/RSWiRFctJPQRAfLGfUTIWqCo",
    "mxc://moritzdietz.com/oPOkWTlBWdTFbwXuGZNxbpAU",
    "mxc://mozilla.org/66d994693725ea09256c22ac43b0e74e79f1abb4",
    "mxc://mpl.mpg.de/lxwOKWWbfwlGxAMKhNIfiJRR",
    "mxc://msg-net.de/uqthdSIKEsmLlAnrguhOBSRg",
    "mxc://mx.anismk.de/hjKAFiGKMasHOCdEVPsmoozA",
    "mxc://mx.grupotd.nat.cu/ZfxNoISumlPZZEHqRNbhewQW",
    "mxc://neko.dev/wLFwLqbnyvrstuomVXdKMqyJ",
    "mxc://nevarro.space/WmGsIGgESPTtJFskYIXdRlVM",
    "mxc://obermui.de/pCkwyNUtzdnaImzuqbsaJCgV",
    "mxc://perthchat.org/sNAywRrlPKygmkoxpfxSTrFz",
    "mxc://pixelplanet.fun/xfxdQZvpLePdlNcRIjoFovPE",
    "mxc://pixie.town/fq3MchyYAMzpCkfxbqr9WffR",
    "mxc://pixie.town/qBpNzYpOknBxnSdcbFWrbqWT",
    "mxc://raim.ist/oInPkqchozNTmIOeUXlCsFbp",
    "mxc://riot.ovh/PJxWnOsjdnIpkByXMFJVGZgE",
    "mxc://rs485.network/XpMPNjUVJmwwVQyaVtkAjpfl",
    "mxc://scamdemic.wtf/WFPdCxatgVIQcYOqkWDKVsXP",
    "mxc://seymour.family/ZlzrDJSjRnQYuWJGvhdCkyiS",
    "mxc://shiina.family/zxIxLfIyoXTeclPZznmIdRli",
    "mxc://simonatherley.com/nYEzJcoThHfARGPSkHXRGapn",
    "mxc://skyforge.at/RExFPAnBOsbCqFZIFHAESyKQ",
    "mxc://stratum0.org/FKcEkoEcEutsdRUaPjQitDwo",
    "mxc://sw1v.org/rARZrbDMGnNQOKKWZtCVxusq",
    "mxc://t2l.io/fYhaPLjAZLwEYqaSGKwRpQgk",
    "mxc://that.host/QbAhNvUApAEpvCKNWtIZwjCO",
    "mxc://the-apothecary.club/HScGQAQKwuQbbdNkLYoPpsNb",
    "mxc://tout.im/VQpPnZfufsMWerGlxkupbtYo",
    "mxc://uhoreg.ca/JbcxMQHvPoPUoRkwQRdmwXKm",
    "mxc://veganism.social/dDVjvEJugTUfWfiavHKhvCxi",
    "mxc://wi11.co.uk/DztCMbxBfOUrmklICETzYOEJ",
    "mxc://yaal.coop/BviDGOwocxQQNndowuZmhxGr",
]


async def request_media(session: aiohttp.ClientSession, media_url: str) -> int:
    media_id = media_url.removeprefix("mxc://")
    url = f"http://localhost:8080/_matrix/media_proxy/unstable/download/{media_id}"

    # timeout = aiohttp.ClientTimeout(total=10)
    async with session.get(url) as response:
        await response.read()
        print(".", end="", flush=True)

        return response.status


async def main() -> None:
    perfdir = os.path.dirname(__file__)
    os.makedirs(os.path.join(perfdir, "temp"), exist_ok=True)

    print(f"number of URLs: {len(AVATAR_URLS_TAKEN_FROM_SYNAPSE_DEV)}")

    server = None
    try:
        server = subprocess.Popen(
            args=[
                sys.executable,
                "-m",
                "matrix_content_scanner.mcs",
                "-c",
                "config.yaml",
            ],
            cwd=perfdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Give server time to startup
        time.sleep(0.5)

        await run_test()
        # Run test a second time, now that caches have warmed up
        await run_test()
    finally:
        if server is not None:
            server.terminate()
            print("Server return code:", server.returncode)


async def run_test() -> None:
    failed = False
    start = timer()
    try:
        async with aiohttp.ClientSession() as session:
            requests = []
            for url in AVATAR_URLS_TAKEN_FROM_SYNAPSE_DEV:
                requests.append(asyncio.ensure_future(request_media(session, url)))

            statuses = await asyncio.gather(*requests)
            print()
            print("Status codes from scanner server:", collections.Counter(statuses))
    except Exception:
        traceback.print_exc()
        failed = True
    finally:
        end = timer()
        duration = end - start
        print(f"{'Failed' if failed else 'Succeeded'} in {duration:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
