# CloudGuard demo

Run (Python 3, no installs needed):

    python3 cloudguard.py scan samples/            # find secrets + risky IAM/Terraform
    python3 cloudguard.py fix samples/bad_policy.json   # suggest least-privilege policy

Block bad commits (inside any git repo):

    printf '#!/bin/sh\npython3 /full/path/to/cloudguard.py precommit\n' > .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit

All keys in samples/ are the official AWS dummy examples, not real credentials.
