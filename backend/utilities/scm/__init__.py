"""Code repositories at scale (F3): org-level SCM connections, discovery into a repository inventory, scan policies
per repository group, a bounded fair queue of repository scans, signed webhooks, credits per run and a
cross-repository roll-up of findings.

    filters.py     include / exclude rules (pure, deterministic) shared by imports and policy selectors
    hosts.py       which SCM API base URLs may be called (SaaS defaults, or hosts in GIT_ALLOWED_HOSTS)
    providers/     GitHub (App installation or token), GitLab group, Bitbucket workspace clients
    inventory.py   idempotent sync of a connection's repositories into ``scmrepository``
    policies.py    which policy a repository falls under, and policy schedules
    pricing.py     credits per repository x product (formula scm-size-v1)
    queue.py       runs, the queue, the fair dispatcher and completion
    rollup.py      fingerprints and the cross-repository roll-up of findings
    webhooks.py    signature checks and push / repository events
"""
