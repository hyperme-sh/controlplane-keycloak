"""Offline contract for the optional Hypermesh login theme."""
import json
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / "keycloak/themes/hypermesh/login"

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "a":
            self.links.append(dict(attrs))

def test_footer_has_public_fixed_links_without_auth_data_or_scripts():
    source = (THEME / "footer.ftl").read_text()
    parser = Links()
    parser.feed(source)
    assert [link["href"] for link in parser.links] == [
        "https://hyperme.sh/privacy", "https://hyperme.sh/terms"]
    assert all(link["rel"] == "noreferrer" for link in parser.links)
    assert "18 and older" in source and "Fyber Labs TN LLC" in source
    assert '${' not in source
    assert not {"script", "form", "input", "iframe"}.intersection(parser.tags)

def test_theme_inherits_forms_and_is_not_selected_by_realm_import():
    assert (THEME / "theme.properties").read_text() == "parent=keycloak.v2\n"
    assert {p.name for p in THEME.iterdir()} == {"footer.ftl", "theme.properties"}
    realm = json.loads((ROOT / "keycloak/import/controlplane-realm.json").read_text())
    assert "loginTheme" not in realm
    assert all("login_theme" not in client.get("attributes", {}) for client in realm["clients"])
