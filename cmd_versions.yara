import "hash"

rule cmd_2003sp1_cn
{
meta:
    author = "wesinator"
    repo = "https://github.com/wesinator/generic-yara-rules"
condition:
    hash.sha256(0, filesize) == "96b715ede9080d52a1d8a6d4018e7a39b8b2837fcba8e092e6b6449b67ee7de4"
}

rule cmd_2003sp2_cn
{
meta:
    author = "wesinator"
    repo = "https://github.com/wesinator/generic-yara-rules"
condition:
    hash.sha256(0, filesize) == "21676e4be8fc0bdc78057b1585668d049aa034fc5459677ba9d7e082077d3c61"
}

rule cmd_xpsp2_cn
{
meta:
    author = "wesinator"
    repo = "https://github.com/wesinator/generic-yara-rules"
condition:
    hash.sha256(0, filesize) == "8e9cbea79e50d3b861f347f25dffd307eb3eec658ed94898e4ad2888772f4e8f"
}

rule cmd_xpsp3_cn
{
meta:
    author = "wesinator"
    repo = "https://github.com/wesinator/generic-yara-rules"
condition:
    hash.sha256(0, filesize) == "906281757a8fa60c78fe9e28b6ddb797d64b65c3558678a793e0330b07e2bd5e"
}

rule cmd_win7_en
{
meta:
    author = "wesinator"
    repo = "https://github.com/wesinator/generic-yara-rules"
condition:
    hash.sha256(0, filesize) == "8deab32f7297bcbc22caa7baeb2ddb6bf36e73d9a7f68b6737c1e4c75e213cb9"
}

rule cmd_win7sp1_en
{
meta:
    author = "wesinator"
    repo = "https://github.com/wesinator/generic-yara-rules"
condition:
    hash.sha256(0, filesize) == "17f746d82695fa9b35493b41859d39d786d32b23a9d2e00f4011dec7a02402ae"
}
