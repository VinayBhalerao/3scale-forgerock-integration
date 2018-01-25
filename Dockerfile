FROM registry.access.redhat.com/3scale-amp20/apicast-gateway:1.0
MAINTAINER Vinay Bhalerao (vinay@redhat.com)

COPY resources/nginx.conf /opt/app-root/src/conf/nginx.conf
COPY resources/keycloak.lua /opt/app-root/src/src/oauth/keycloak.lua