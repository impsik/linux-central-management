import bz2

from app.services.cve_sync import parse_oval_bz2_file


def test_stream_parser_preserves_package_index_children(tmp_path):
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition class="vulnerability" id="oval:test:def:1" version="1">
      <metadata><title>CVE-2026-1234 on Ubuntu 24.04 LTS (noble) - high</title></metadata>
      <criteria><criterion test_ref="oval:test:tst:1" /></criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:test:tst:1" version="1">
      <linux-def:object object_ref="oval:test:obj:1" />
      <linux-def:state state_ref="oval:test:ste:1" />
    </linux-def:dpkginfo_test>
  </tests>
  <objects>
    <linux-def:dpkginfo_object id="oval:test:obj:1" version="1">
      <linux-def:name>example-package</linux-def:name>
    </linux-def:dpkginfo_object>
  </objects>
  <states>
    <linux-def:dpkginfo_state id="oval:test:ste:1" version="1">
      <linux-def:evr operation="less than">1.2.3-0ubuntu1</linux-def:evr>
    </linux-def:dpkginfo_state>
  </states>
</oval_definitions>
"""
    oval_path = tmp_path / "noble.oval.xml.bz2"
    oval_path.write_bytes(bz2.compress(xml))

    parsed = {}
    parse_oval_bz2_file(str(oval_path), "noble", parsed)

    assert parsed == {
        "CVE-2026-1234": {
            "noble": {
                "packages": {
                    "example-package": {
                        "status": "released",
                        "fixed_version": "1.2.3-0ubuntu1",
                    }
                }
            }
        }
    }
