"""Scanner plugins grouped by target type (dns/, ip/, web/, code/, binary/).

Production plugins are imported explicitly by the process entry points (`workers.app` and
`app.create_app`) so registration happens once and a profile can never name an unimported
plugin. Never crawl packages for plugins: add each production module to those imports.
"""
