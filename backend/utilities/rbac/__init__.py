"""Role-based access control for teams (F4): the permission matrix, the route policies and the audit log.

* ``permissions``  the matrix (roles owner > admin > member > viewer, and what each may do)
* ``policy``       the dependency every route declares (``Access(get_db).team("scan.read")``, ``public(...)``)
* ``audit``        the append-only, hash-chained audit log and its middleware
* ``coverage``     the check that every route declares a policy
"""
from backend.utilities.rbac.permissions import (  # noqa: F401
    ADMIN_ROLES,
    PERMISSIONS,
    ROLES,
    assignable_roles,
    invitable_roles,
    is_admin_role,
    permissions_for,
    role_has,
)
from backend.utilities.rbac.policy import Access, Principal, machine, public  # noqa: F401
