#!/bin/bash

# automation of certificate renewal for let's encrypt and haproxy
# - checks all certificates under /etc/letsencrypt/live and renews
#   those about about to expire in less than 4 weeks
# - creates haproxy.pem files in /etc/letsencrypt/live/domain.tld/
# - soft-restarts haproxy to apply new certificates
# usage:
# sudo ./cert-renewal-haproxy.sh

###################
## configuration ##
###################

EMAIL=${EMAIL:-set_me_in_env@gmail.com}
FORCE_RENEW=${FORCE_RENEW:-0}
DAYS=${DAYS:-30}
LE_CLIENT=${LE_CLIENT:-certbot}
HAPROXY_RELOAD_CMD=${HAPROXY_RELOAD_CMD:-service haproxy reload}
WEBROOT=${WEBROOT:-/var/lib/haproxy}
LOGFILE="/var/log/certrenewal.log"
# Set to 1 to redirect output to logfile (for silent cron jobs)
LOGTOFILE=${LOGTOFILE:-0}

######################
## utility function ##
######################

function issueCert {
  # if only 1 dot i.e. domain.com -> add www.domain.com to signing
  DOMAIN=$1
  DOTS=`echo "$DOMAIN" | awk -F. '{ print NF - 1 }'`
  ADD_DOMAINS=""
  if [ "$DOTS" = "1" ]; then
    ADD_DOMAINS="-d www.$DOMAIN"
    logger_error "Also issuing for www.$DOMAIN"
  fi
  $LE_CLIENT certonly --text --webroot --webroot-path ${WEBROOT} --renew-by-default --agree-tos --email ${EMAIL} -d $DOMAIN $ADD_DOMAINS
  return $?
}

function logger_error {
  if [ $LOGTOFILE -gt 0 ]; then
    echo "[error] [$(date +'%d.%m.%y - %H:%M')] ${1}" >> ${LOGFILE}
  else
    (>&2 echo "[error] ${1}")
  fi
}

function logger_info {
  if [ $LOGTOFILE -gt 0 ]; then
    echo "[info] [$(date +'%d.%m.%y - %H:%M')] ${1}" >> ${LOGFILE}
  else
    echo "[info] ${1}"
  fi
}

##################
## main routine ##
##################

le_cert_root="/etc/letsencrypt/live"

if [ ! -d ${le_cert_root} ]; then
  logger_error "${le_cert_root} does not exist!"
  exit 1
fi

# check certificate expiration and run certificate issue requests
# for those that expire in under 4 weeks
renewed_certs=()
exitcode=0
SECS=`expr $DAYS \* 86400`
while read domain; do
  latest_folder=` ls -1 ${le_cert_root} | grep ^${domain} | sort | tail -n1 `
  cert=${le_cert_root}/${latest_folder}/cert.pem
  logger_info "${cert} name ${certname} latest ${latest_folder}"

  need=0
  if ! openssl x509 -noout -checkend $SECS -in "${cert}"; then
    need=1
  fi
  if [ "$FORCE_RENEW" = "1" ]; then
    need=1
  fi

  if [ "$need" = "1" ]; then
    subject="$(openssl x509 -noout -subject -in "${cert}" | grep -o -E 'CN=[^ ,]+' | tr -d 'CN=')"
    subjectaltnames="$(openssl x509 -noout -text -in "${cert}" | sed -n '/X509v3 Subject Alternative Name/{n;p}' | sed 's/\s//g' | tr -d 'DNS:' | sed 's/,/ /g')"
    domains="${subject}"
    for name in ${subjectaltnames}; do
      if [ "${name}" != "${subject}" ]; then
        domains="${domains} -d ${name}"
      fi
    done
    issueCert "${domains}"
    if [ $? -ne 0 ]
    then
      logger_error "failed to renew certificate! check /var/log/letsencrypt/letsencrypt.log!"
      exitcode=1
    else
      renewed_certs+=("$subject")
      logger_info "renewed certificate for ${subject}"
    fi
  else
    logger_info "none of the certificates requires renewal"
  fi
done < <(ls -1 ${le_cert_root} | grep -vE -- "-0[0-9]+")

# reissue for domains declared but no existing in letsencrypt dir
for N in `cat /etc/haproxy/haproxy.cfg | grep "ssl crt" | grep -v "crt-list" | sed -re "s/.*ssl crt//g"`; do
    if [ -f $N ]; then
	logger_info "skipping existing declared cert $N"
    else
	certdir=`dirname $N`
	domain=`basename ${certdir}`
	logger_info "issuing for $domain"
	issueCert ${domain}
	if [ $? -ne 0 ]
	then
    	    logger_error "failed to renew certificate! check /var/log/letsencrypt/letsencrypt.log!"
    	    exitcode=1
	else
    	    renewed_certs+=("$subject")
    	    logger_info "renewed certificate for ${subject}"
	fi
    fi
done

# reissue for domains declared but no existing in letsencrypt dir (crt-list)
for F in `cat /etc/haproxy/haproxy.cfg | grep "ssl crt-list" | sed -re "s/.*ssl crt-list//g"`; do
    logger_info "reading $F for certificate list"
    for N in `cat $F`; do
	if [ -f $N ]; then
	    logger_info "skipping existing declared cert $N"
	else
	    certdir=`dirname $N`
	    domain=`basename ${certdir}`
	    logger_info "issuing for $domain"
	    issueCert ${domain}
	    if [ $? -ne 0 ]
	    then
    		logger_error "failed to renew certificate! check /var/log/letsencrypt/letsencrypt.log!"
    		exitcode=1
	    else
    		renewed_certs+=("$subject")
    		logger_info "renewed certificate for ${subject}"
	    fi
	fi
    done
done

# recreate crtlist.txt
echo -n >/etc/haproxy/crtlist.new
while read domain; do
  latest_folder=` ls -1 ${le_cert_root} | grep ^${domain} | sort | tail -n1 `
  cert=${le_cert_root}/${latest_folder}/cert.pem
  logger_info "${cert} name ${certname} latest ${latest_folder}"
  if [ -f ${cert} ]; then
    cat ${le_cert_root}/${latest_folder}/privkey.pem ${le_cert_root}/${latest_folder}/fullchain.pem > ${le_cert_root}/${latest_folder}/haproxy.pem
  else
    rm -Rf ${le_cert_root}/${latest_folder}/haproxy.pem
  fi
  echo ${le_cert_root}/${latest_folder}/haproxy.pem>>/etc/haproxy/crtlist.new
done < <(ls -1 ${le_cert_root} | grep -vE -- "-0[0-9]+")
mv /etc/haproxy/crtlist.new /etc/haproxy/crtlist.txt

# soft-restart haproxy
if [ "${#renewed_certs[@]}" -gt 0 ]; then
  logger_info "reloading haproxy"
  $HAPROXY_RELOAD_CMD
  if [ $? -ne 0 ]; then
    logger_error "failed to reload haproxy!"
    exit 1
  fi
fi

exit ${exitcode}
