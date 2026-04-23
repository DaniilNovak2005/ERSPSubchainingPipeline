#!/bin/bash
# SAILOR config for OpenSSL 3.5.5
#
# Analysis target: libcrypto + libssl (crypto/, ssl/, providers/) only
# Excluded: apps/ (openssl CLI), test/, fuzz/, demos/, docs/

export EXTRA_CFLAGS="-I${SRC_ROOT}/include -I${SRC_ROOT}"

# Tool/CLI file basenames to exclude (apps/ directory)
export TOOL_FILES="asn1parse.c,ca.c,ciphers.c,cmp.c,cms.c,crl2pkcs7.c,crl.c,dgst.c,dhparam.c,dsa.c,dsaparam.c,ec.c,ecparam.c,enc.c,engine.c,errstr.c,fipsinstall.c,gendsa.c,genpkey.c,genrsa.c,info.c,kdf.c,list.c,mac.c,nseq.c,ocsp.c,openssl.c,passwd.c,pkcs12.c,pkcs7.c,pkcs8.c,pkey.c,pkeyparam.c,pkeyutl.c,prime.c,rand.c,rehash.c,req.c,rsa.c,rsautl.c,s_client.c,sess_id.c,skeyutl.c,smime.c,speed.c,spkac.c,srp.c,s_server.c,s_time.c,storeutl.c,ts.c,verify.c,version.c,vms_decc_init.c,x509.c,app_libctx.c,app_params.c,app_provider.c,app_rand.c,apps.c,apps_opt_printf.c,apps_ui.c,app_x509.c,cmp_mock_srv.c,columns.c,engine_loader.c,fmt.c,http_server.c,log.c,names.c,opt.c,s_cb.c,s_socket.c,tlssrp_depr.c,vms_decc_argv.c,vms_term_sock.c,win32_init.c"

# Test/fuzz/demo files — not part of core library
export NON_LIBRARY_FILES=""

# Upstream URL for concrete verification
export UPSTREAM_URL="https://github.com/openssl/openssl.git"

# Parallelism
export PARALLEL_JOBS=128
