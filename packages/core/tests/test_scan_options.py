from sentinel_core import scan_options


def test_resolve_defaults_and_known_values():
    assert scan_options.resolve(None) == (5.0, 100)
    assert scan_options.resolve({"speed": "gentle", "depth": "deep"}) == (2.0, 300)
    assert scan_options.resolve({"speed": "bogus", "depth": None}) == (5.0, 100)


def test_recon_profile_defaults_to_light_for_old_or_unknown_values():
    assert scan_options.resolve_recon_profile(None) == "light"
    assert scan_options.resolve_recon_profile({}) == "light"  # scans from before profiles
    assert scan_options.resolve_recon_profile({"recon_profile": "bogus"}) == "light"
    assert scan_options.resolve_recon_profile({"recon_profile": None}) == "light"
    assert scan_options.resolve_recon_profile({"recon_profile": "light"}) == "light"


def test_recon_profile_full_is_only_given_when_asked_for():
    assert scan_options.resolve_recon_profile({"recon_profile": "full"}) == "full"
