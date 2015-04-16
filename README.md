# Misc MarkLogic Scripts

# backup-multiple-databases.xqy

Allows you to perform multiple manual backups of various databases at one time in MarkLogic.


# dump-security.xqy

Allows you to dump/load/diff security from MarkLogic in plain text without having to see the security namespace/security ids. Currently 90% of commands must be ran against the security database. It also doesn't dump/load/diff everything but things I have personally chosen to do so far. 

Currently covered by dump:

* Users
** name
** description
** permissions
** roles attached
** default collections 

* Roles
** name
** description
** permissions
** roles attached
** default collections 

* Amps
** namespace
** local-name
** document-uri
** database (name)
** roles attached

Currently covered by load:

* Users
** name
** permissions
** roles attached

* Roles
** name
** permissions
** roles attached

Currently covered by diff:

* Users
** name
** roles attached

* Roles
** name
** roles attached
