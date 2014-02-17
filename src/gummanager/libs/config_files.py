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
    location = /{instance_name} {{rewrite ^([^.]*[^/])$ $1/ permanent;}}

    location ~* ^/{instance_name}/stomp {{
        proxy_set_header X-Virtual-Host-URI $scheme://{server_dns}/{instance_name};
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/(.*) /$1 break;
        proxy_pass    http://rabbitmq_web_stomp_server;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
     }}

    location ~* ^/{instance_name}/(?!contexts|people|activities|conversations|admin|auth).*$ {{
        proxy_set_header X-Virtual-Host-URI $scheme://{server_dns}/{instance_name};
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/(.*) /$1 break;

        proxy_pass    http://{server_dns}:{bigmax_port};
     }}

    location ~ ^/{instance_name}/(.*) {{

        if ($request_method = 'OPTIONS') {{

            # Tell client that this pre-flight info is valid for 20 days
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain charset=UTF-8';
            add_header 'Content-Length' 0;

            return 200;
        }}

        proxy_set_header X-Virtual-Host-URI $scheme://{server_dns}/{instance_name};
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/(.*) /$1 break;

        proxy_pass   http://{server_dns}:{max_port};
    }}
"""
