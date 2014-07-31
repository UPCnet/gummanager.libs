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
CONFDIR=$WORKDIR/config
ENDPOINT={port_index}

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

    location ~* ^/{instance_name}/(?!contexts|people|activities|conversations|messages|admin|info).*$ {{
        proxy_set_header X-Virtual-Host-URI $scheme://{server_dns};
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;
        rewrite ^/{instance_name}/(.*) /{instance_name}/$1 break;

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
CIRCUS_NGINX_ENTRY = """
  server {{
   listen   {circus_nginx_port};
   server_name  localhost;

   location / {{

     proxy_http_version 1.1;
     proxy_set_header Upgrade $http_upgrade;
     proxy_set_header Connection "upgrade";
     proxy_set_header Host $host:$server_port;
     proxy_set_header X-Real-IP $remote_addr;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     proxy_set_header X-Forwarded-Proto http;
     proxy_set_header X-Forwarded-Host $host:$server_port;
     proxy_pass http://localhost:{circus_httpd_endpoint};
     auth_basic            "Restricted";
     auth_basic_user_file  /var/nginx/config/circus.htpasswd;
    }}
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
max_server   = https://{server_dns}/{instance_name}
stomp_server = https://{server_dns}/{instance_name}/stomp
oauth_server = https://{oauth_dns}/{oauth_name}
"""

MAXBUNNY_INSTANCE_ENTRY = """[max_{name}]
hashtag = {hashtag}
server = {server}
oauth_server = {oauth_server}
restricted_user = {restricted_user}
restricted_user_token = {restricted_user_token}
language = {language}
"""
