# RDAP fixtures

Trimmed excerpts of IANA's RDAP DNS bootstrap registry (`iana_bootstrap.json`) and a `.com`
RDAP domain response (`rdap_com_example.json`), recorded 2026-11-13 and reduced to the fields
the adapter reads (`services`, `events`, `status`, the registrar entity). They contain only
public registration data for `example.com`, no credentials or private information. Tests never
touch the network.
