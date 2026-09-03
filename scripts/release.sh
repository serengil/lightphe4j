  make verify                               # full chain incl. all 120 tests — the only gate, since CI skips them                                
  make release-check GPG_KEY=<FINGERPRINT>  # signs everything, uploads nothing; prompts for your passphrase
  make release GPG_KEY=<FINGERPRINT>        # signs and uploads a staged deployment