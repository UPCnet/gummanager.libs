LDAP_INI = """[ldap]
server = ldaps://
userbind = cn=ldap,ou=,dc=upcnet,dc=es
password = secret
userbasedn = ou=,dc=upcnet,dc=es
userfilter = (cn=%(login)s)
userscope = SCOPE_SUBTREE
groupbasedn = ou=groups,ou=,dc=upcnet,dc=es
groupfilter = (&(objectClass=groupOfNames)(member=%(userdn)s))
groupscope = SCOPE_SUBTREE
groupcache = 600
"""

INIT_D_SCRIPT = """#!/bin/sh
# chkconfig: - 85 15
# description: Arranque de los servicios relacionados con la instancia de oauth

WORKDIR={instance_folder}
CONFDIR=$WORKDIR/config
ENDPOINT=141{port_index}

case "$1" in
'start')
        $WORKDIR/bin/circusd $CONFDIR/circus.ini --daemon
;;
'stop')
        $WORKDIR/bin/circusctl --endpoint tcp://127.0.0.1:$ENDPOINT stop
        $WORKDIR/bin/circusctl --endpoint tcp://127.0.0.1:$ENDPOINT quit
;;
'restart')
        $WORKDIR/bin/circusctl --endpoint tcp://127.0.0.1:$ENDPOINT restart
;;
*)
    echo "Usage: /etc/init.d/oauth_<CLIENT> {{ start | stop | restart }}"
    ;;
esac
exit 0
"""

OSIRIS_NGINX_ENTRY = """
    location = /{instance_name} {{rewrite ^([^.]*[^/])$ $1/ permanent;}}
    location ~ ^/{instance_name}/(.*) {{
        proxy_set_header X-Virtual-Host-URI $scheme://{server_dns};
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/(.*) /$1 break;

        proxy_pass   http://{server_dns}:{osiris_port};
    }}
"""

MAX_NGINX_ENTRY = """
"""