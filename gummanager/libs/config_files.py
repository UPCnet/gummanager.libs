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

WORKDIR={instance_folder}

case "$1" in
'start')
        $WORKDIR/bin/supervisord
;;
'stop')
        $WORKDIR/bin/supervisorctl stop all
        $WORKDIR/bin/supervisorctl shutdown
;;
'restart')
        $WORKDIR/bin/circusctl restart all
;;
*)
    echo "Usage: $0 {{ start | stop | restart }}"
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

        proxy_pass   http://{server}:{osiris_port};
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

    location ~* ^/{instance_name}/(?!contexts|people|activities|conversations|messages|admin|info).*$ {{
        proxy_set_header X-Virtual-Host-URI $scheme://{server_dns};
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/(.*) /{instance_name}/$1 break;

        proxy_pass    http://{server}:{bigmax_port};
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

        proxy_pass   http://{server}:{max_port};
    }}
"""


ULEARN_NGINX_ENTRY = """
    # MAX passthrough for legacy IE compat
    location = /{instance_name}/max {{
        rewrite ^([^.]*[^/])$ $1/ permanent;
    }}

    location ~* ^/{instance_name}/max/stomp {{
        proxy_set_header X-Virtual-Host-URI $scheme://$host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/max/(.*) /$1 break;
        proxy_pass    http://rabbitmq_web_stomp_server;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
     }}


    location ~ ^/{instance_name}/max/(.*) {{
        proxy_set_header X-Virtual-Host-URI $scheme://$host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;

        rewrite ^/{instance_name}/max/(.*) /$1 break;
        proxy_pass {max_server};
    }}

    location ~ ^/{instance_name}($|/.*) {{
        proxy_set_header X-Virtual-Host-URI $scheme://$host:$server_port;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;

        rewrite ^/{instance_name}($|/.*) /VirtualHostBase/$scheme/$host:$server_port/{mountpoint_id}/{instance_name}/VirtualHostRoot/_vh_{instance_name}$1 break;
        proxy_pass   http://genweb_server;
    }}
"""

BIGMAX_INSTANCE_ENTRY = """[{instance_name}]
server   = https://{server_dns}/{instance_name}
"""

MAXBUNNY_INSTANCE_ENTRY = """[{name}]
hashtag = {hashtag}
server = {server}
restricted_user = {restricted_user}
restricted_user_token = {restricted_user_token}
language = {language}
"""
